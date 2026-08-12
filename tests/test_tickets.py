"""Tests for the ticket verifier.

These are the tests that matter most in the whole service: every expensive code
path sits behind `require_ticket`, so a regression here is a regression in the
billing.  Each case below corresponds to one way an attacker gets a ticket they
should not be able to use.

Environment is populated before importing anything from `app` because
`app.settings` instantiates its `Settings` at import time.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import pytest

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("TICKET_SECRET", "unit-test-ticket-secret-do-not-ship")
os.environ.setdefault("IP_SALT", "unit-test-ip-salt")
os.environ.setdefault("TURNSTILE_SECRET", "unit-test-turnstile-secret")
os.environ.setdefault("ALLOWED_ORIGINS", "https://example.test")
os.environ.setdefault("R2_ACCOUNT_ID", "acct")
os.environ.setdefault("R2_ACCESS_KEY_ID", "key")
os.environ.setdefault("R2_SECRET_ACCESS_KEY", "secret")
os.environ.setdefault("R2_BUCKET", "bucket")
os.environ.setdefault("R2_PUBLIC_BASE", "https://cdn.example.test")
os.environ.setdefault("METRICS_TOKEN", "metrics")
os.environ.setdefault("DAILY_SPEND_CAP_MICRO_USD", "50000000")

from starlette.requests import Request  # noqa: E402

from app.errors import ApiError  # noqa: E402
from app.security import tickets  # noqa: E402
from app.security.quotas import hash_ip  # noqa: E402

CLIENT_IP = "203.0.113.10"
OTHER_IP = "198.51.100.7"

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Redis double
# ---------------------------------------------------------------------------


class MiniRedis:
    """Just enough Redis to exercise SET NX EX semantics honestly.

    Written by hand rather than reached for from `fakeredis` so the replay test
    depends on nothing but the semantics we actually rely on: NX must refuse to
    overwrite a live key, and an expired key must behave as absent.  If
    `fakeredis` is installed the `redis_backend` fixture runs every test against
    it as well, so the double cannot quietly drift from the real thing.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float | None]] = {}

    def _live(self, key: str) -> str | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and expires_at <= time.time():
            del self._store[key]
            return None
        return value

    async def set(
        self,
        key: str,
        value: Any,
        *,
        nx: bool = False,
        ex: int | None = None,
    ) -> bool | None:
        if nx and self._live(key) is not None:
            return None
        self._store[key] = (str(value), time.time() + ex if ex else None)
        return True

    async def get(self, key: str) -> str | None:
        return self._live(key)

    async def delete(self, key: str) -> int:
        return 1 if self._store.pop(key, None) is not None else 0


@pytest.fixture(params=["double", "fakeredis"])
def redis_backend(request: pytest.FixtureRequest) -> Any:
    if request.param == "fakeredis":
        fakeredis = pytest.importorskip("fakeredis")
        return fakeredis.aioredis.FakeRedis(decode_responses=True)
    return MiniRedis()


@pytest.fixture(autouse=True)
def patch_redis(monkeypatch: pytest.MonkeyPatch, redis_backend: Any) -> Any:
    async def _get_redis() -> Any:
        return redis_backend

    monkeypatch.setattr(tickets, "get_redis", _get_redis)
    return redis_backend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_request(ticket: str | None, ip: str = CLIENT_IP) -> Request:
    """A real Starlette Request, so `require_ticket` is exercised as deployed."""
    headers: list[tuple[bytes, bytes]] = [(b"host", b"downloader.test")]
    if ticket is not None:
        headers.append((b"x-download-ticket", ticket.encode("utf-8")))
    headers.append((b"x-forwarded-for", ip.encode("utf-8")))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/resolve",
        "raw_path": b"/v1/resolve",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("10.0.0.1", 51234),
        "server": ("downloader.test", 443),
    }
    return Request(scope)


def forge(payload: dict[str, Any]) -> str:
    """Sign an arbitrary payload with the real secret (valid MAC, bad claims)."""
    payload_b64 = tickets._b64url_encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )
    return f"{payload_b64}.{tickets._sign(payload_b64)}"


async def assert_api_error(code: str, coro: Any) -> ApiError:
    with pytest.raises(ApiError) as excinfo:
        await coro
    assert excinfo.value.code == code, f"expected {code}, got {excinfo.value.code}"
    return excinfo.value


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_valid_ticket_passes() -> None:
    ticket = tickets.mint_ticket(CLIENT_IP)
    claims = await tickets.require_ticket(make_request(ticket))

    assert claims.aud == tickets.TICKET_AUDIENCE
    assert claims.ip_hash == hash_ip(CLIENT_IP)
    assert claims.exp > int(time.time())
    assert len(claims.jti) == 32


async def test_missing_header_rejected() -> None:
    await assert_api_error("ticket_missing", tickets.require_ticket(make_request(None)))


async def test_tampered_signature_rejected() -> None:
    payload_b64, _, signature = tickets.mint_ticket(CLIENT_IP).partition(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]

    await assert_api_error(
        "ticket_bad_signature",
        tickets.require_ticket(make_request(f"{payload_b64}.{flipped}")),
    )


async def test_tampered_payload_rejected() -> None:
    """Rewriting the claims invalidates the MAC that covers the payload text."""
    original = tickets.mint_ticket(OTHER_IP)
    payload_b64, _, signature = original.partition(".")
    swapped = tickets._b64url_encode(
        json.dumps(
            {
                "jti": "f" * 32,
                "aud": tickets.TICKET_AUDIENCE,
                "exp": int(time.time()) + 120,
                "ip_hash": hash_ip(CLIENT_IP),
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    assert swapped != payload_b64

    await assert_api_error(
        "ticket_bad_signature",
        tickets.require_ticket(make_request(f"{swapped}.{signature}")),
    )


async def test_malformed_ticket_rejected() -> None:
    for junk in ("", "no-dot-here", ".", "a.b.c", "!!!.???"):
        expected = "ticket_missing" if junk == "" else "ticket_bad_signature"
        await assert_api_error(expected, tickets.require_ticket(make_request(junk)))


async def test_expired_ticket_rejected() -> None:
    stale = tickets.mint_ticket(CLIENT_IP, ttl_s=-60)
    await assert_api_error("ticket_expired", tickets.require_ticket(make_request(stale)))


async def test_absurd_lifetime_rejected() -> None:
    """A correctly signed ticket good for a year means a broken minter."""
    long_lived = forge(
        {
            "jti": "a" * 32,
            "aud": tickets.TICKET_AUDIENCE,
            "exp": int(time.time()) + 365 * 24 * 3600,
            "ip_hash": hash_ip(CLIENT_IP),
        }
    )
    await assert_api_error("ticket_expired", tickets.require_ticket(make_request(long_lived)))


async def test_replay_rejected_on_second_use() -> None:
    ticket = tickets.mint_ticket(CLIENT_IP)

    await tickets.require_ticket(make_request(ticket))
    await assert_api_error("ticket_replayed", tickets.require_ticket(make_request(ticket)))


async def test_concurrent_replay_admits_exactly_one(patch_redis: Any) -> None:
    """The property SET NX buys us, stated as a test.

    A GET-then-SET verifier passes every other test in this file and fails this
    one, because both coroutines observe an unspent jti before either writes.
    """
    import asyncio

    ticket = tickets.mint_ticket(CLIENT_IP)
    results = await asyncio.gather(
        *(tickets.require_ticket(make_request(ticket)) for _ in range(8)),
        return_exceptions=True,
    )

    accepted = [r for r in results if not isinstance(r, BaseException)]
    replayed = [r for r in results if isinstance(r, ApiError) and r.code == "ticket_replayed"]
    assert len(accepted) == 1
    assert len(replayed) == 7


async def test_wrong_audience_rejected() -> None:
    ticket = forge(
        {
            "jti": "b" * 32,
            "aud": "portfolio-contact-form",
            "exp": int(time.time()) + 120,
            "ip_hash": hash_ip(CLIENT_IP),
        }
    )
    await assert_api_error("ticket_wrong_audience", tickets.require_ticket(make_request(ticket)))


async def test_ip_hash_mismatch_rejected() -> None:
    """A ticket lifted off the wire is useless from a different address."""
    ticket = tickets.mint_ticket(CLIENT_IP)
    await assert_api_error(
        "ticket_bad_signature",
        tickets.require_ticket(make_request(ticket, ip=OTHER_IP)),
    )


async def test_ip_mismatch_does_not_burn_the_ticket() -> None:
    """Otherwise an eavesdropper could invalidate other people's tickets."""
    ticket = tickets.mint_ticket(CLIENT_IP)

    await assert_api_error(
        "ticket_bad_signature",
        tickets.require_ticket(make_request(ticket, ip=OTHER_IP)),
    )
    claims = await tickets.require_ticket(make_request(ticket, ip=CLIENT_IP))
    assert claims.ip_hash == hash_ip(CLIENT_IP)


async def test_leftmost_forwarded_for_entry_is_the_client() -> None:
    """The first X-Forwarded-For entry wins, matching what the minter reads.

    This replaced a rightmost-Nth-hop rule that had to know how many proxies sat
    in front. That count is a property of the deployment, not of the code — 1 on
    a bare Railway domain, 2 behind Cloudflare — and every wrong guess presented
    identically: `ip_mismatch`, a 401, no clue why.

    Spoofing the header is not a way around the quotas. Every limit is keyed off
    `claims.ip_hash`, which comes out of the HMAC-signed ticket rather than out
    of this header (see `consume_resolve_quota` / `consume_bytes_quota` call
    sites). Forging an address here only makes the check below fail, so it costs
    the attacker their own ticket and gains them nothing.
    """
    ticket = tickets.mint_ticket(CLIENT_IP)
    request = make_request(ticket, ip=f"{CLIENT_IP}, 10.0.0.7")

    claims = await tickets.require_ticket(request)
    assert claims.ip_hash == hash_ip(CLIENT_IP)


async def test_forged_forwarded_for_fails_rather_than_bypassing_the_binding() -> None:
    """A client-chosen address does not silently become the trusted one."""
    ticket = tickets.mint_ticket(CLIENT_IP)
    request = make_request(ticket, ip=f"1.2.3.4, {CLIENT_IP}")

    await assert_api_error("ticket_bad_signature", tickets.require_ticket(request))


async def test_ticket_from_a_different_secret_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    ticket = tickets.mint_ticket(CLIENT_IP)
    monkeypatch.setattr(tickets, "_ticket_secret", lambda: b"a-completely-different-secret")

    await assert_api_error("ticket_bad_signature", tickets.require_ticket(make_request(ticket)))


async def test_oversize_ticket_rejected_without_parsing() -> None:
    await assert_api_error(
        "ticket_bad_signature",
        tickets.require_ticket(make_request("x" * (tickets.MAX_TICKET_BYTES + 1))),
    )


async def test_burnt_jti_key_has_a_ttl(patch_redis: Any) -> None:
    """An immortal jti set is how Redis runs out of memory in three months."""
    ticket = tickets.mint_ticket(CLIENT_IP)
    claims = await tickets.require_ticket(make_request(ticket))

    key = f"jti:{claims.jti}"
    assert await patch_redis.get(key) is not None
    if hasattr(patch_redis, "ttl"):  # only the real/fake Redis exposes TTL
        assert 0 < int(await patch_redis.ttl(key)) <= tickets.JTI_BURN_TTL_S


def test_hash_ip_is_stable_and_not_reversible() -> None:
    assert hash_ip(CLIENT_IP) == hash_ip(CLIENT_IP)
    assert hash_ip(CLIENT_IP) != hash_ip(OTHER_IP)
    assert len(hash_ip(CLIENT_IP)) == 16
    assert CLIENT_IP not in hash_ip(CLIENT_IP)
