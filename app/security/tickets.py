"""Single-use, IP-bound HMAC tickets.

WHY tickets exist
-----------------
`/v1/resolve` and `/v1/jobs` cost real money: a yt-dlp extraction is a burst of
outbound requests, and a job is worker CPU plus proxy bandwidth.  Turnstile
proves a human was present *at the website*, but Turnstile tokens are validated
by Cloudflare, not by us, and a browser cannot hold a long-lived secret.  A
ticket is the bridge: the Next.js route verifies Turnstile server-side, then
mints a 120-second, single-use, IP-bound HMAC blob that this service can verify
with nothing but a shared secret and one Redis round trip.  It converts the
expensive endpoints from "anyone with curl" into "someone who solved a
challenge in the last two minutes, from this IP, once".

Wire format (must stay byte-identical to contrib/mint-ticket.ts):

    base64url(payload_json) + "." + base64url(hmac_sha256(secret, payload_b64))

    payload = {"jti": <32 hex>, "aud": "downloader", "exp": <unix s>,
               "ip_hash": <16 hex>}

The signature covers the *base64url text* of the payload, not the decoded JSON.
That is intentional: it removes any dependence on both sides serialising JSON
identically (key order, whitespace, unicode escaping) and means verification
never has to re-encode attacker-controlled data before checking it.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import time
import uuid
from hashlib import sha256
from typing import Any, Final, NoReturn

from fastapi import Request

from app.errors import ApiError
from app.logging_conf import log
from app.models import TicketClaims
from app.redis_conn import get_redis
from app.security.quotas import hash_ip
from app.settings import settings

TICKET_HEADER: Final[str] = "X-Download-Ticket"
TICKET_AUDIENCE: Final[str] = "downloader"

#: Lifetime used when minting.  Short enough that a ticket scraped from a HAR
#: file or a shared devtools screenshot is dead before it can be traded.
TICKET_TTL_S: Final[int] = 120

#: Hard ceiling accepted at verification time.  A correctly signed ticket with
#: a one-year expiry can only come from our own minting route, so this is not
#: about forgery - it is about blast radius if that route is ever misconfigured
#: or a debug value ships to production.
MAX_TICKET_TTL_S: Final[int] = 300

#: The burnt-jti marker outlives the ticket itself.  If it expired at the same
#: moment as the ticket there would be a window where a ticket is simultaneously
#: too old to be valid and no longer recorded as spent - harmless today, but it
#: makes the invariant "a spent jti is remembered for longer than any ticket can
#: live" true unconditionally, which is what a reviewer needs to be able to see.
JTI_BURN_TTL_S: Final[int] = 300

#: Tolerance for clock drift between the Vercel edge that mints and the Railway
#: container that verifies.  Both run NTP; 5s is generous and still far shorter
#: than the ticket lifetime.
CLOCK_SKEW_S: Final[int] = 5

#: Number of reverse proxies in front of this service that we control (Railway's
#: edge = 1).  The client IP is taken this many entries from the RIGHT of
#: X-Forwarded-For, never the left.  The leftmost entry is whatever the client
#: chose to send; the rightmost entries are appended by infrastructure we trust.
#: Set this wrong and quota evasion becomes a one-line curl flag.
TRUSTED_PROXY_HOPS: Final[int] = 1

#: Refuse absurd header values before spending CPU on them.
MAX_TICKET_BYTES: Final[int] = 1024


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    """base64url with padding stripped - the form the TS minter emits."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    """Decode unpadded base64url, restoring the '=' padding Python requires."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _ticket_secret() -> bytes:
    """Return the HMAC key as bytes.

    Accepts either a plain ``str`` or a pydantic ``SecretStr`` so this module
    does not care how ``Settings`` chose to declare the field.
    """
    secret: Any = settings.ticket_secret
    if hasattr(secret, "get_secret_value"):
        secret = secret.get_secret_value()
    if isinstance(secret, bytes):
        return secret
    return str(secret).encode("utf-8")


def _sign(payload_b64: str) -> str:
    mac = hmac.new(_ticket_secret(), payload_b64.encode("ascii"), sha256).digest()
    return _b64url_encode(mac)


def _fail(code: str, detail: str, **ctx: Any) -> NoReturn:
    """Log the precise reason, return the coarse reason.

    The client is told which of the five ticket failure modes applies because
    that genuinely helps a legitimate browser recover (re-mint vs. re-challenge).
    Anything finer grained - "your ip_hash was X, we computed Y" - stays in the
    logs, where it is an operational aid rather than an oracle.
    """
    log.warning("ticket_rejected", extra={"code": code, **ctx})
    raise ApiError(code, detail=detail)


# ---------------------------------------------------------------------------
# Client address
# ---------------------------------------------------------------------------


def client_ip(request: Request) -> str:
    """Best-effort real client address, resistant to header spoofing.

    Railway's edge appends the observed peer address to ``X-Forwarded-For``.  A
    client that pre-sets the header produces ``"1.2.3.4, <real>"``; taking the
    entry ``TRUSTED_PROXY_HOPS`` from the right therefore yields the real one
    and ignores the forged prefix entirely.

    Note what happens to an attacker who spoofs anyway: the value here stops
    matching the ``ip_hash`` baked into their ticket by the minting route (which
    saw an address the client could not influence), so the request is rejected
    outright.  Spoofing X-Forwarded-For against this service is not a quota
    bypass, it is a self-inflicted 401.
    """
    # Cloudflare sets CF-Connecting-IP to the true client address and strips any
    # copy the client tried to send, so where it exists it is both simpler and
    # safer than counting X-Forwarded-For hops.
    #
    # Counting hops is what broke here: the documented topology is
    # client -> Cloudflare -> Railway -> app, which appends TWO entries, so
    # TRUSTED_PROXY_HOPS=1 selected Cloudflare's edge address. Every ticket then
    # failed its ip_hash check and the whole service returned 401 — with the
    # least debuggable symptom available. The minter must read the same header;
    # see contrib/mint-ticket.ts.
    cf_ip = request.headers.get("cf-connecting-ip", "").strip()
    if cf_ip:
        return cf_ip

    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            index = max(len(parts) - TRUSTED_PROXY_HOPS, 0)
            return parts[index]
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    return request.client.host if request.client else ""


# ---------------------------------------------------------------------------
# Minting (used by tests, ops tooling, and as executable spec for the TS side)
# ---------------------------------------------------------------------------


def mint_ticket(ip: str, ttl_s: int = TICKET_TTL_S, *, now: int | None = None) -> str:
    """Produce a ticket this module will accept.

    Production tickets are minted at the edge by contrib/mint-ticket.ts; this
    function exists so the format has one authoritative, testable definition in
    the same repository as the verifier.  ``separators=(",", ":")`` and the
    literal key order below are what make the two implementations byte-equal.
    """
    issued = int(time.time()) if now is None else now
    payload = {
        "jti": uuid.uuid4().hex,
        "aud": TICKET_AUDIENCE,
        "exp": issued + int(ttl_s),
        "ip_hash": hash_ip(ip),
    }
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )
    return f"{payload_b64}.{_sign(payload_b64)}"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _parse(raw: str) -> tuple[str, dict[str, Any]]:
    """Split, authenticate and decode a ticket. Returns (payload_b64, payload).

    Every structural failure is reported as ``ticket_bad_signature``.  A
    malformed ticket and a forged ticket are the same event from the caller's
    perspective, and collapsing them denies an attacker a parser oracle that
    tells them how far through validation their input got.
    """
    if len(raw) > MAX_TICKET_BYTES:
        _fail("ticket_bad_signature", "Invalid ticket.", reason="oversize", size=len(raw))

    payload_b64, sep, signature_b64 = raw.partition(".")
    if not sep or not payload_b64 or not signature_b64:
        _fail("ticket_bad_signature", "Invalid ticket.", reason="malformed")

    expected = _sign(payload_b64)
    # compare_digest, never ==: a byte-wise early-exit comparison leaks the
    # position of the first mismatch through timing, which is enough to forge a
    # signature one byte at a time given enough attempts.
    if not hmac.compare_digest(expected, signature_b64):
        _fail("ticket_bad_signature", "Invalid ticket.", reason="signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        # Reachable only with a valid signature over garbage, i.e. our own
        # minter emitted something broken. Still handled rather than crashed.
        _fail("ticket_bad_signature", "Invalid ticket.", reason="undecodable_payload")

    if not isinstance(payload, dict):
        _fail("ticket_bad_signature", "Invalid ticket.", reason="payload_not_object")

    return payload_b64, payload


def _claims_from_payload(payload: dict[str, Any]) -> TicketClaims:
    try:
        jti = str(payload["jti"])
        aud = str(payload["aud"])
        exp = int(payload["exp"])
        ip_hash = str(payload["ip_hash"])
    except (KeyError, TypeError, ValueError):
        _fail("ticket_bad_signature", "Invalid ticket.", reason="incomplete_payload")

    if not jti or len(jti) > 64:
        _fail("ticket_bad_signature", "Invalid ticket.", reason="bad_jti")

    return TicketClaims(jti=jti, aud=aud, exp=exp, ip_hash=ip_hash)


async def _burn(jti: str) -> None:
    """Consume the ticket's one and only use.

    WHY this is a single atomic ``SET key 1 NX EX`` and not GET-then-SET:
    read-then-write is two round trips with a gap in between, and two requests
    carrying the same replayed ticket can both execute the GET inside that gap,
    both see "not spent", and both proceed.  Under exactly the conditions where
    replay protection matters - an attacker firing a captured ticket at high
    concurrency - the check reliably fails open.  SET NX pushes the decision
    into Redis's single-threaded command execution, where exactly one caller can
    be the one that created the key.  The falsy return *is* the replay signal;
    it needs no follow-up read.

    EX (rather than a bare SET) is the other half: without a TTL the jti set
    grows forever and eventually becomes the memory limit that takes Redis down.
    """
    redis = await get_redis()
    created = await redis.set(f"jti:{jti}", "1", nx=True, ex=JTI_BURN_TTL_S)
    if not created:
        _fail("ticket_replayed", "This ticket was already used.", jti=jti)


async def verify_ticket(raw: str | None, peer_ip: str) -> TicketClaims:
    """Full verification pipeline. Raises ``ApiError`` on any failure.

    Ordering is deliberate and cheapest-first: presence, then signature (pure
    CPU, no I/O, and nothing downstream may trust unauthenticated fields), then
    audience and expiry, then the IP binding, and only then the Redis write that
    actually consumes the ticket.
    """
    if not raw:
        _fail("ticket_missing", "A download ticket is required.", reason="absent")

    _payload_b64, payload = _parse(raw.strip())
    claims = _claims_from_payload(payload)

    if not hmac.compare_digest(claims.aud, TICKET_AUDIENCE):
        _fail(
            "ticket_wrong_audience",
            "This ticket was not issued for this service.",
            aud=claims.aud,
        )

    now = int(time.time())
    if claims.exp < now - CLOCK_SKEW_S:
        _fail("ticket_expired", "Ticket expired. Please retry.", exp=claims.exp, now=now)

    if claims.exp > now + MAX_TICKET_TTL_S + CLOCK_SKEW_S:
        # Correctly signed but with an implausible lifetime: treat as expired
        # (the honest client-facing outcome is "get a new one") and shout in the
        # logs, because it means the minting route is misconfigured.
        log.error("ticket_ttl_implausible", extra={"exp": claims.exp, "now": now})
        _fail("ticket_expired", "Ticket expired. Please retry.", reason="ttl_too_long")

    expected_ip_hash = hash_ip(peer_ip)
    if not hmac.compare_digest(claims.ip_hash, expected_ip_hash):
        # Checked BEFORE the burn on purpose.  If the jti were consumed first,
        # anyone who observed a ticket in flight could invalidate it from their
        # own machine and deny service to the legitimate holder - a griefing
        # primitive handed out for free.  Failing here leaves the real user's
        # ticket untouched and still usable.
        _fail(
            "ticket_bad_signature",
            "Invalid ticket.",
            reason="ip_mismatch",
            claimed=claims.ip_hash,
            observed=expected_ip_hash,
        )

    await _burn(claims.jti)

    log.info("ticket_accepted", extra={"jti": claims.jti, "ip_hash": claims.ip_hash})
    return claims


async def require_ticket(request: Request) -> TicketClaims:
    """FastAPI dependency: ``claims: TicketClaims = Depends(require_ticket)``.

    Downstream code must key quotas off ``claims.ip_hash`` rather than
    recomputing one, so that every counter is anchored to a value that survived
    an HMAC check.
    """
    return await verify_ticket(request.headers.get(TICKET_HEADER), client_ip(request))
