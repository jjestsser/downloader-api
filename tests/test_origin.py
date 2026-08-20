"""Tests for the edge-proof guard and the address it decides to believe.

These cover a hole that was measured against the deployed service on
2026-08-21, not one that was theorised. `client_ip` read `CF-Connecting-IP`
unconditionally; a ticket minted for 198.51.100.7 and presented to the live
service with `CF-Connecting-IP: 198.51.100.7` was accepted, putting the caller
in a per-IP quota bucket of their own choosing. The same attempt through
`X-Forwarded-For` was refused, because Railway's proxy overwrites that header
and does not touch the other one.

Environment is populated before importing anything from `app` because
`app.settings` instantiates its `Settings` at import time.
"""

from __future__ import annotations

import os

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
from app.security import origin, tickets  # noqa: E402
from app.settings import settings  # noqa: E402

EDGE_SECRET = "edge-token-for-tests"


def make_request(headers: dict[str, str], client: str = "10.0.0.1") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/resolve",
            "headers": raw,
            "client": (client, 12345),
        }
    )


@pytest.fixture
def with_edge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "origin_shared_token", EDGE_SECRET, raising=False)


@pytest.fixture
def without_edge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "origin_shared_token", "", raising=False)


class TestTheAddressWeBelieve:
    def test_cf_header_is_ignored_when_no_edge_is_configured(self, without_edge: None) -> None:
        # The measured hole. Nothing strips this header on a bare Railway
        # hostname, so without proof of an edge it is a string the caller chose.
        request = make_request(
            {"cf-connecting-ip": "198.51.100.7", "x-forwarded-for": "203.0.113.1"}
        )
        assert tickets.client_ip(request) == "203.0.113.1"

    def test_cf_header_is_ignored_when_the_edge_token_is_wrong(self, with_edge: None) -> None:
        request = make_request(
            {
                "cf-connecting-ip": "198.51.100.7",
                "x-edge-token": "not-the-secret",
                "x-forwarded-for": "203.0.113.1",
            }
        )
        assert tickets.client_ip(request) == "203.0.113.1"

    def test_cf_header_is_believed_once_the_edge_vouches_for_it(self, with_edge: None) -> None:
        # Behind Cloudflare the header is both authoritative and stripped of any
        # copy the caller sent, so it is the best value available.
        request = make_request(
            {
                "cf-connecting-ip": "198.51.100.7",
                "x-edge-token": EDGE_SECRET,
                "x-forwarded-for": "203.0.113.1",
            }
        )
        assert tickets.client_ip(request) == "198.51.100.7"

    def test_takes_the_rightmost_forwarded_entry(self, without_edge: None) -> None:
        # The leftmost is whatever the caller claimed; the rightmost is what the
        # proxy in front observed. `clientIpFrom` in
        # src/lib/tools/download/ticket.ts takes the same end of the list, and
        # the two must agree or every request 401s with no explanation.
        request = make_request({"x-forwarded-for": "198.51.100.7, 203.0.113.1"})
        assert tickets.client_ip(request) == "203.0.113.1"

    def test_no_header_a_caller_controls_can_choose_the_address(
        self, without_edge: None
    ) -> None:
        chosen = "198.51.100.7"
        for headers in (
            {"cf-connecting-ip": chosen},
            {"x-forwarded-for": f"{chosen}, 203.0.113.1"},
            {"cf-connecting-ip": chosen, "x-edge-token": "guessed"},
        ):
            assert tickets.client_ip(make_request(headers)) != chosen, headers


class TestTheOriginGuard:
    @pytest.mark.anyio
    async def test_passes_everything_through_when_unconfigured(
        self, without_edge: None
    ) -> None:
        # The service has to keep working before the Cloudflare rule exists, and
        # in local development where there is no edge at all.
        await origin.require_edge(make_request({}))

    @pytest.mark.anyio
    async def test_refuses_a_request_that_reached_the_origin_directly(
        self, with_edge: None
    ) -> None:
        with pytest.raises(ApiError) as caught:
            await origin.require_edge(make_request({}))
        # 404, not 403: a prober learns the hostname serves nothing interesting,
        # rather than learning they found the right service and need one header.
        assert caught.value.status_code == 404

    @pytest.mark.anyio
    async def test_admits_a_request_carrying_the_shared_secret(
        self, with_edge: None
    ) -> None:
        await origin.require_edge(make_request({"x-edge-token": EDGE_SECRET}))

    def test_came_through_edge_is_false_when_unconfigured(self, without_edge: None) -> None:
        # Deliberately not True. Treating "no secret set" as "everything is
        # trusted" would restore the exact trust this module exists to withdraw.
        assert origin.came_through_edge(make_request({"x-edge-token": "anything"})) is False
