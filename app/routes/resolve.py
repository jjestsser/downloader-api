"""POST /v1/resolve — metadata and format list for one URL.

## The gate order is deliberate and is expressed in the signature

FastAPI resolves dependencies in declaration order, so `killswitch_guard` runs
before `require_ticket`. That ordering is the point: when the daily spend cap
has tripped, the service should answer 503 without spending CPU on an HMAC
verification and a Redis round-trip for a request it is going to refuse anyway.

Inside the handler the remaining gates run cheapest-first — platform detection
is a regex, the degraded check is one Redis GET, the quota is an INCR, and only
then do we pay for a network call to the platform.

## Why this endpoint is the cheap one

For everything in `DIRECT_HANDOFF` the response carries `direct_url` on each
format and `delivery="direct"`, and the browser fetches the CDN itself. This
service moves zero bytes. The expensive path is `POST /v1/jobs`, which is why
Turnstile guards that one and not this one.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.errors import ApiError
from app.logging_conf import log
from app.models import ResolveResponse, TicketClaims
from app.resolver import canary, platforms, ytdlp
from app.security.origin import require_edge
from app.security.quotas import check_killswitch, consume_resolve_quota
from app.security.tickets import require_ticket

# `require_edge` is a no-op until ORIGIN_SHARED_TOKEN is set, and setting it
# requires a Cloudflare Transform Rule in front of this service. Until then the
# real protection is that `client_ip` no longer believes CF-Connecting-IP
# without proof — see app/security/origin.py.
router = APIRouter(prefix="/v1", tags=["resolve"], dependencies=[Depends(require_edge)])


async def killswitch_guard() -> None:
    """Refuse everything while the global spend cap is tripped."""
    await check_killswitch()


@router.post("/resolve", response_model=ResolveResponse)
async def resolve_url(
    request: Request,
    _: None = Depends(killswitch_guard),
    claims: TicketClaims = Depends(require_ticket),
) -> ResolveResponse:
    body = await request.json()
    raw_url = body.get("url") if isinstance(body, dict) else None
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ApiError("unsupported_platform", "Paste a link to get started.")

    url = platforms.normalize_url(raw_url)
    if url is None:
        raise ApiError("unsupported_platform")

    if platforms.is_playlist_url(url):
        # One playlist URL must never fan out into hundreds of jobs.
        raise ApiError("playlist_rejected")

    platform = platforms.detect_platform(url)
    if platform is None:
        raise ApiError("unsupported_platform")

    if await canary.platform_state(platform) == canary.STATE_DEGRADED:
        raise ApiError(
            "platform_degraded",
            f"{platform.title()} downloads are temporarily unavailable. Try again shortly.",
        )

    await consume_resolve_quota(claims.ip_hash)

    result = await ytdlp.resolve(url, platform)

    # URL hash only — never the URL. See app/logging_conf.py.
    log.info(
        "resolved",
        platform=platform,
        url_hash=ytdlp.url_hash(url),
        delivery=result.delivery,
        formats=len(result.formats),
    )
    return result
