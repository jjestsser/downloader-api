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
from app.security.origin import came_through_edge
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
    """Best-effort real client address, for logging and nothing else.

    This value is no longer compared against the ``ip_hash`` in the ticket.
    Measured 2026-08-21 on a real visitor: the minting route saw 112.134.221.2
    and this service saw 152.233.68.97, same browser, same moment, both correct
    — a CGNAT pool egressing different connections from different addresses. The
    comparison locked out every such visitor, so `require_ticket` now records a
    difference and carries on. The quota key is the signed ``ip_hash`` from the
    ticket itself.

    The rule below still matters, because the *minting* route uses the same
    logic to decide which bucket a caller lands in, and a caller must not be
    able to choose that. An earlier version of this docstring argued that
    spoofing was self-defeating: the value
    computed here would stop matching the ``ip_hash`` in the attacker's ticket,
    so the request would 401. That is true of an attacker who spoofs one side.
    It is false of one who spoofs both, which is the whole attack — present the
    same fabricated address to the minting route and to this service, watch the
    two agree, and land in a per-IP quota bucket nobody else is using. Repeat
    with the next address for another. The daily caps stop being caps.

    Measured against the deployed service on 2026-08-21: a ticket minted for
    198.51.100.7 and presented with ``CF-Connecting-IP: 198.51.100.7`` was
    accepted; the same trick through ``X-Forwarded-For`` was refused, because
    Railway's proxy overwrites that header and does not touch the other one.
    """
    # Cloudflare sets CF-Connecting-IP to the true client and strips any copy the
    # caller sent — but only when Cloudflare is actually in front. On a bare
    # *.up.railway.app hostname nothing strips it, so without proof that the
    # request came through the edge it is just a string the caller chose.
    if came_through_edge(request):
        cf_ip = request.headers.get("cf-connecting-ip", "").strip()
        if cf_ip:
            return cf_ip

    # LEFTMOST X-Forwarded-For entry.
    #
    # MEASURED 2026-08-21, from this service's own forwarding_topology log on a
    # real request:
    #
    #   xff        = "112.134.221.2, 152.233.68.97"
    #   x_real_ip  = "112.134.221.2"
    #   peer       = "112.134.221.2"
    #
    # Railway APPENDS its own proxy address, so the last entry is Railway, not
    # the visitor. The first entry is the client and agrees with `x-real-ip` and
    # with what the minting route derives.
    #
    # This was briefly changed to the rightmost entry on the theory that the
    # leftmost is caller-controlled and therefore unsafe. That is the correct
    # rule for the open internet and the wrong one here, and the cost of getting
    # it wrong was total: every ticket's ip_hash stopped matching, the tool
    # failed for everyone, and the mismatch looked so much like two genuinely
    # different addresses that it was misread as a CGNAT pool. It was not.
    #
    # The leftmost entry is not attacker-controlled on this deployment: uvicorn
    # runs with `--proxy-headers --forwarded-allow-ips='*'` behind Railway's
    # proxy, which REPLACES a caller-supplied header rather than appending to
    # it. Measured the same day: a forged `X-Forwarded-For` did not survive to
    # this function, while a forged `CF-Connecting-IP` did — which is why that
    # one is now gated on edge proof and this one is not.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        entries = [part.strip() for part in forwarded.split(",") if part.strip()]
        if entries:
            return entries[0]

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    # uvicorn has already resolved this from the proxy headers it trusts.
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

    # The address is recorded, not enforced.
    #
    # This used to reject when the presenting address differed from the minting
    # one. Measured 2026-08-21 against a real visitor: the minting route saw
    # 112.134.221.2 and this service saw 152.233.68.97 — same browser, same
    # moment, both values correct. The ISP is CGNAT and egresses different
    # connections from different addresses in a pool, so there is no single
    # "the visitor's address" for the two services to agree on. Every such
    # visitor was locked out of the tool completely, and no choice of
    # X-Forwarded-For rule can fix it because neither side was wrong.
    #
    # What the check bought: "whoever presents this ticket is where it was
    # minted." What survives without it: the ticket is HMAC-signed, single use
    # (the jti burn below), lives 120 seconds, and is only issued after a
    # Turnstile solve. Using one from elsewhere means intercepting it in flight
    # and beating the legitimate holder inside that window, which needs MITM or
    # XSS — and anyone holding those has better things to attack.
    #
    # `claims.ip_hash` remains the quota key, and it is trustworthy for that:
    # it is inside the signature, so a caller cannot choose their own bucket,
    # and the minting route no longer believes a caller-supplied
    # CF-Connecting-IP (see app/security/origin.py).
    observed_ip_hash = hash_ip(peer_ip)
    if not hmac.compare_digest(claims.ip_hash, observed_ip_hash):
        # Worth seeing in the logs — a sudden flood of these on a network that
        # used to be quiet is a signal, and it is how the CGNAT case above was
        # identified in the first place.
        log.info(
            "ticket_ip_moved",
            extra={
                "claimed": claims.ip_hash,
                "observed": observed_ip_hash,
                "peer_ip": peer_ip,
            },
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
    _log_forwarding_topology_once(request)
    return await verify_ticket(request.headers.get(TICKET_HEADER), client_ip(request))


_topology_logged = False


def _log_forwarding_topology_once(request: Request) -> None:
    """Record how many proxies actually sit in front, once per process.

    How the edge fills X-Forwarded-For is a property of the deployment, and
    getting it wrong takes down the whole service behind an error message that
    names the wrong cause. Nothing in the code can discover it, so the first
    request of each boot writes it down. Reading one log line beats another
    round of deploy-and-guess.
    """
    global _topology_logged
    if _topology_logged:
        return
    _topology_logged = True
    log.info(
        "forwarding_topology",
        extra={
            "xff": request.headers.get("x-forwarded-for", ""),
            "cf_connecting_ip": request.headers.get("cf-connecting-ip", ""),
            "x_real_ip": request.headers.get("x-real-ip", ""),
            "peer": request.client.host if request.client else "",
            "derived": client_ip(request),
        },
    )
