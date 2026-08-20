"""POST /v1/jobs and GET /v1/jobs/{job_id} — the worker path.

## Why Turnstile guards this endpoint and not /v1/resolve

`/v1/resolve` costs one metadata call. A job costs CPU seconds, egress, and
possibly residential-proxy bytes at ~$3/GiB. Turnstile is friction, and friction
belongs on the expensive door. It is verified server-side here: a client that
"passed" the widget proves nothing, because the widget runs on the client.

## Job ownership

A job is bound to the `ip_hash` of the ticket that created it, and
`GET /v1/jobs/{id}` refuses ids belonging to anyone else. It answers
`job_not_found` rather than a distinct forbidden code — a 403 would confirm the
id exists, which turns job ids into an enumeration oracle for other people's
downloads.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.errors import ApiError
from app.jobs.queue import enqueue_download, job_status
from app.logging_conf import log
from app.models import JobCreateRequest, JobStatus, TicketClaims
from app.resolver import canary, platforms
from app.resolver.ytdlp import url_hash
from app.security.origin import require_edge
from app.security.quotas import check_killswitch, consume_resolve_quota
from app.security.tickets import require_ticket
from app.security.turnstile import verify_turnstile
from app.settings import settings

# `require_edge` is a no-op until ORIGIN_SHARED_TOKEN is set, and setting it
# requires a Cloudflare Transform Rule in front of this service. Until then the
# real protection is that `client_ip` no longer believes CF-Connecting-IP
# without proof — see app/security/origin.py.
router = APIRouter(prefix="/v1", tags=["jobs"], dependencies=[Depends(require_edge)])

TURNSTILE_HEADER = "X-Turnstile-Token"


async def killswitch_guard() -> None:
    await check_killswitch()


@router.post("/jobs", response_model=JobStatus, status_code=202)
async def create_job(
    payload: JobCreateRequest,
    request: Request,
    _: None = Depends(killswitch_guard),
    claims: TicketClaims = Depends(require_ticket),
) -> JobStatus:
    url = platforms.normalize_url(payload.url)
    if url is None:
        raise ApiError("unsupported_platform")
    if platforms.is_playlist_url(url):
        raise ApiError("playlist_rejected")

    platform = platforms.detect_platform(url)
    if platform is None:
        raise ApiError("unsupported_platform")

    if await canary.platform_state(platform) == canary.STATE_DEGRADED:
        raise ApiError(
            "platform_degraded",
            f"{platform.title()} downloads are temporarily unavailable. Try again shortly.",
        )

    # Only enforced when a secret is configured, so local development and tests
    # do not need a Cloudflare account to exercise the worker path.
    if settings.turnstile_secret:
        token = request.headers.get(TURNSTILE_HEADER, "")
        client_ip = request.client.host if request.client else ""
        if not await verify_turnstile(token, client_ip):
            raise ApiError("turnstile_failed")

    # Before anything is spent. The byte quota is otherwise charged only once
    # the file exists, so without this check a caller already over their daily
    # allowance still pulls every subsequent download in full before being told
    # no — a refusal that costs the operator exactly what a success would.
    await assert_bytes_budget_available(claims.ip_hash)

    # A job is at least as expensive as a resolve, so it costs a resolve slot too.
    await consume_resolve_quota(claims.ip_hash)

    job_id = await enqueue_download(
        {
            "url": url,
            "format_id": payload.format_id,
            "mode": payload.mode,
            "platform": platform,
            "ip_hash": claims.ip_hash,
        }
    )

    log.info("job_created", job_id=job_id, platform=platform, url_hash=url_hash(url), mode=payload.mode)
    return await job_status(job_id, claims.ip_hash)


@router.get("/jobs/{job_id}", response_model=JobStatus)
async def read_job(
    job_id: str,
    claims: TicketClaims = Depends(require_ticket),
) -> JobStatus:
    """Poll a job.

    Deliberately not behind the killswitch: a job that already ran should still
    be collectable after the cap trips, or a user loses a download they have
    already been charged for.
    """
    if not job_id or len(job_id) > 64 or not job_id.isalnum():
        raise ApiError("job_not_found")
    return await job_status(job_id, claims.ip_hash)
