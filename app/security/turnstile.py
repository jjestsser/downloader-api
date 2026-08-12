"""Server-side Cloudflare Turnstile verification.

WHY the widget's own success callback is worthless as a security signal
----------------------------------------------------------------------
The Turnstile widget runs in the visitor's browser and hands JavaScript a
token.  Everything about that - whether the challenge ran, whether it passed,
what the token contains - is under the control of whoever owns the browser.  An
attacker does not have to defeat the challenge; they delete it.  A `curl` with
`-H 'cf-turnstile-response: anything'` never loads the widget at all, and a
`if (turnstileOk) callApi()` check in client code is one devtools breakpoint
away from `true`.

The token is only evidence once Cloudflare confirms, from server to server,
that *it* issued that specific token, for our sitekey, recently, and that it has
not been redeemed before.  That confirmation is this module.  It is the only
place in the system where "a human was present" becomes a fact rather than a
claim, which is why the failure mode below is closed rather than open.
"""

from __future__ import annotations

import asyncio
from typing import Any, Final

import httpx

from app.logging_conf import log
from app.settings import settings

SITEVERIFY_URL: Final[str] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

#: Turnstile tokens are ~2 KB at the top end; anything larger is not a token and
#: is not worth an outbound HTTP request.
MAX_TOKEN_LEN: Final[int] = 4096

#: The whole point of a timeout here is that a hung siteverify must not hold a
#: worker slot open. Connect fast, give the response a few seconds, then give up
#: and fail closed.
_TIMEOUT: Final[httpx.Timeout] = httpx.Timeout(6.0, connect=2.5)

#: One retry, and only for transport-level failures. Turnstile tokens are
#: single-redemption: retrying after a *response* would burn the token and get
#: back `timeout-or-duplicate`, turning a transient blip into a hard failure.
_MAX_ATTEMPTS: Final[int] = 2

_client: httpx.AsyncClient | None = None
_client_lock: Final[asyncio.Lock] = asyncio.Lock()


async def _get_client() -> httpx.AsyncClient:
    """Lazily create one shared client so TLS handshakes are amortised."""
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    timeout=_TIMEOUT,
                    limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
                    headers={"user-agent": "downloader-turnstile/1.0"},
                )
    return _client


async def aclose_turnstile_client() -> None:
    """Called from the FastAPI lifespan shutdown hook."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _turnstile_secret() -> str:
    secret: Any = getattr(settings, "turnstile_secret", "") or ""
    if hasattr(secret, "get_secret_value"):
        secret = secret.get_secret_value()
    return str(secret)


async def verify_turnstile(token: str, ip: str) -> bool:
    """Ask Cloudflare whether ``token`` is a genuine, unredeemed challenge pass.

    Returns ``True`` only on an explicit ``success: true`` from Cloudflare.
    Every other outcome - malformed token, network failure, timeout, non-200,
    unparseable body, missing secret in production - returns ``False``.

    Failing closed is the correct default even though it means a Cloudflare
    outage temporarily blocks new downloads.  The alternative, failing open, has
    the property that the cheapest way to bypass the challenge is to make our
    siteverify call fail - a capability any client already has by flooding us
    until the outbound connection pool starves.  A gate that opens under load is
    not a gate.  Availability of a free media downloader is worth less than the
    bill an open gate produces.
    """
    if not token or len(token) > MAX_TOKEN_LEN:
        log.warning("turnstile_rejected", extra={"reason": "token_shape"})
        return False

    secret = _turnstile_secret()
    if not secret:
        if str(getattr(settings, "environment", "production")).lower() != "production":
            # Local dev without a Cloudflare account should not be impossible.
            # This branch cannot execute in production by construction.
            log.warning("turnstile_bypassed_dev", extra={"reason": "no_secret"})
            return True
        log.error("turnstile_misconfigured", extra={"reason": "no_secret_in_production"})
        return False

    payload = {"secret": secret, "response": token, "remoteip": ip}
    client = await _get_client()

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = await client.post(SITEVERIFY_URL, data=payload)
        except httpx.HTTPError as exc:
            log.warning(
                "turnstile_transport_error",
                extra={"attempt": attempt, "error": type(exc).__name__},
            )
            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(0.25 * attempt)
                continue
            return False

        if response.status_code != 200:
            # A 5xx from Cloudflare is retryable in principle, but the token may
            # already be spent, so treat it as terminal and fail closed.
            log.warning("turnstile_http_error", extra={"status": response.status_code})
            return False

        try:
            body = response.json()
        except ValueError:
            log.warning("turnstile_bad_body", extra={})
            return False

        success = bool(body.get("success"))
        if not success:
            # `error-codes` is the diagnostic that distinguishes "bot" from
            # "our secret is wrong", and it is safe to log: it contains no
            # token, no IP and no URL.
            log.warning(
                "turnstile_failed",
                extra={"error_codes": body.get("error-codes", []) or []},
            )
        return success

    return False
