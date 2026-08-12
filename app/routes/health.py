"""Liveness, readiness and metrics.

WHY /healthz and /readyz are different endpoints:

  /healthz is LIVENESS. "Is this process alive and its event loop responsive?"
  It must never depend on anything external. If it fails, the only sane remedy
  is to kill and restart the container — so it returns 200 whenever the process
  can answer at all. Wiring Redis into liveness is a classic self-inflicted
  outage: Redis blips, every container fails its liveness probe, the platform
  restarts all of them at once, and now there is a cold start stampede on top of
  the original blip.

  /readyz is READINESS. "Should this instance receive traffic right now?" Every
  meaningful request needs Redis (tickets, quotas, killswitch), so with Redis
  unreachable this instance can serve nothing but errors and returns 503 until
  it recovers. No restart, no stampede — just removed from rotation.

/metrics is token-protected because the counters describe abuse patterns and
spend, and because an unauthenticated metrics endpoint is a free oracle for
anyone probing the quota system.
"""

from __future__ import annotations

import hmac
import threading
import time
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Header, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from redis.exceptions import RedisError

from app.logging_conf import log
from app.redis_conn import get_redis, ping
from app.settings import settings
from app.storage import r2

router = APIRouter(tags=["ops"])

_PROCESS_START = time.time()

MetricKey = tuple[str, tuple[tuple[str, str], ...]]

#: name -> (prometheus type, HELP text)
METRIC_META: Final[dict[str, tuple[str, str]]] = {
    "downloader_resolves_total": ("counter", "Resolve requests handled, by platform and outcome."),
    "downloader_jobs_total": ("counter", "Download jobs observed, by lifecycle state."),
    "downloader_ticket_rejections_total": ("counter", "Rejected download tickets, by reason."),
    "downloader_bytes_served_total": (
        "counter",
        "Bytes moved through the worker. Direct CDN handoffs contribute zero.",
    ),
    "downloader_platform_degraded": (
        "gauge",
        "1 when the health canary has marked a platform degraded, else 0.",
    ),
    "downloader_killswitch_active": ("gauge", "1 when the global killswitch is set."),
    "downloader_spend_micro_usd_today": ("gauge", "Recorded egress spend for the current UTC day."),
    "downloader_uptime_seconds": ("gauge", "Seconds since this process started."),
}


class _Counters:
    """In-process counters.

    WHY in-process rather than a Prometheus client library: this service runs a
    small, fixed number of instances and the numbers that matter for money and
    abuse (spend, quotas, killswitch) are already in Redis and read live below.
    These counters exist to make a single instance's behaviour legible; they
    reset on deploy and that is fine.
    """

    __slots__ = ("_lock", "_values")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[MetricKey, float] = {}

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> MetricKey:
        return name, tuple(sorted((str(k), str(v)) for k, v in labels.items()))

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + value

    def set(self, name: str, value: float, **labels: str) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._values[key] = value

    def snapshot(self) -> dict[MetricKey, float]:
        with self._lock:
            return dict(self._values)


COUNTERS: Final[_Counters] = _Counters()


# --------------------------------------------------------------------------- #
# Recording helpers. Other modules import these instead of touching COUNTERS.
# --------------------------------------------------------------------------- #


def record_resolve(platform: str, outcome: str = "ok") -> None:
    COUNTERS.inc("downloader_resolves_total", platform=platform, outcome=outcome)


def record_job(state: str) -> None:
    COUNTERS.inc("downloader_jobs_total", state=state)


def record_ticket_rejection(reason: str) -> None:
    COUNTERS.inc("downloader_ticket_rejections_total", reason=reason)


def record_bytes_served(n: int) -> None:
    if n > 0:
        COUNTERS.inc("downloader_bytes_served_total", float(n))


# --------------------------------------------------------------------------- #
# Prometheus text rendering
# --------------------------------------------------------------------------- #


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render(samples: dict[MetricKey, float]) -> str:
    lines: list[str] = []
    by_name: dict[str, list[tuple[tuple[tuple[str, str], ...], float]]] = {}
    for (name, labels), value in samples.items():
        by_name.setdefault(name, []).append((labels, value))

    for name in sorted(by_name):
        metric_type, help_text = METRIC_META.get(name, ("untyped", name))
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")
        for labels, value in sorted(by_name[name]):
            if labels:
                rendered = ",".join(f'{k}="{_escape_label(v)}"' for k, v in labels)
                lines.append(f"{name}{{{rendered}}} {value:g}")
            else:
                lines.append(f"{name} {value:g}")
    return "\n".join(lines) + "\n"


async def _redis_gauges() -> dict[MetricKey, float]:
    """Read the live operational state out of Redis.

    Deliberately best-effort: a metrics scrape must never be the thing that
    takes the service down, so any Redis failure just omits these series.
    """
    gauges: dict[MetricKey, float] = {}
    try:
        client = await get_redis()

        # Read through the canary module rather than the raw keys. `canary:*` is
        # a HASH, so the previous MGET raised WRONGTYPE — and because that sits
        # inside this one try block, it also took out the killswitch and spend
        # gauges below, which are the two series that exist to tell you money is
        # leaking. The sentinel was wrong too: the canary writes
        # "healthy"/"degraded"/"unknown", never "ok", so every healthy platform
        # would have reported degraded.
        from app.resolver.canary import STATE_DEGRADED, all_platform_states

        for platform, state in (await all_platform_states()).items():
            degraded = 1.0 if state == STATE_DEGRADED else 0.0
            gauges[("downloader_platform_degraded", (("platform", platform),))] = degraded

        killswitch = await client.get("killswitch:global")
        gauges[("downloader_killswitch_active", ())] = 1.0 if killswitch else 0.0

        day = time.strftime("%Y%m%d", time.gmtime())
        spend = await client.get(f"spend:{day}")
        gauges[("downloader_spend_micro_usd_today", ())] = float(spend or 0)
    except (RedisError, OSError, ValueError):
        log.warning("metrics_redis_read_failed", exc_info=True)
    return gauges


def _metrics_token_ok(authorization: str | None, x_metrics_token: str | None) -> bool:
    expected = settings.metrics_token
    if not expected:
        # No token configured: allowed only outside production, where /metrics is
        # a development convenience rather than an exposed surface.
        return not settings.is_production
    presented = x_metrics_token or ""
    if not presented and authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    return bool(presented) and hmac.compare_digest(presented, expected)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@router.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    """Liveness: 200 for as long as the process can answer. No dependencies."""
    return JSONResponse({"status": "ok", "uptime_s": round(time.time() - _PROCESS_START, 1)})


#: R2 readiness is cached: /readyz is polled by the platform, and a HeadBucket on
#: every poll is a needless round trip to Cloudflare. Short enough that a fixed
#: bucket shows up within a minute of the fix.
_R2_PROBE_TTL_S: Final[int] = 30
_r2_probe: dict[str, Any] = {"at": 0.0, "why": None}


async def _r2_ready() -> tuple[str, str | None]:
    """Actually talk to the bucket, rather than counting non-empty env vars.

    This reported "configured" while every worker job died on upload. Four
    populated environment variables say nothing about whether the credentials are
    valid, the bucket exists, or the endpoint is reachable — and the one thing
    that does say so, `r2.health()`, was already written here and never called.
    A readiness probe that cannot fail is not a probe.

    Deliberately NOT part of the 503 decision. R2 is only needed by the worker
    path; `/v1/resolve` and every direct-CDN handoff work without it, so a bucket
    outage should degrade this service, not remove it from rotation.
    """
    if not settings.r2_configured:
        return "unconfigured", None

    now = time.time()
    if now - _r2_probe["at"] > _R2_PROBE_TTL_S:
        _r2_probe["why"] = await r2.health()
        _r2_probe["at"] = now

    why = _r2_probe["why"]
    if why is None:
        return "up", None
    # The reason names the bucket and endpoint, which is the whole point — those
    # two are what is usually wrong — but they are ours, not a caller's business.
    return "down", None if settings.is_production else why


def _scratch_ready() -> str:
    """Can this process actually create a per-job working directory?

    Same lesson as R2, one layer down. `SCRATCH_DIR` is the only writable path in
    the image, and `download_job` starts by creating a subdirectory of it. If that
    fails the job dies before its first progress update, reports `internal`, and
    every other signal the service emits stays green — the API answers, Redis is
    up, `/v1/resolve` works, because none of them write a file.

    The mode is deployment-dependent, which is exactly why it needs checking at
    runtime rather than reasoning about: the Dockerfile creates /scratch owned by
    uid 10001, and a volume mounted over that path may arrive owned by root.

    Cheap enough to run unconditionally — one mkdir and one rmdir on local disk —
    so unlike the R2 probe it is not cached. A stale answer here would be worse
    than the round trip it saves.
    """
    probe = Path(settings.scratch_dir) / ".readyz-probe"
    try:
        probe.mkdir(parents=True, exist_ok=True)
        probe.rmdir()
        return "writable"
    except OSError as exc:
        log.warning(
            "scratch_unwritable",
            extra={"path": settings.scratch_dir, "error": f"{type(exc).__name__}: {exc}"},
        )
        return "unwritable"


@router.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness: 503 while Redis is unreachable, because nothing works without it."""
    redis_ok = await ping()
    r2_state, r2_why = await _r2_ready()
    payload: dict[str, Any] = {
        "status": "ready" if redis_ok else "not_ready",
        "redis": "up" if redis_ok else "down",
        "r2": r2_state,
        "scratch": _scratch_ready(),
        "env": settings.environment,
    }
    if r2_why:
        payload["r2_detail"] = r2_why
    status_code = 200 if redis_ok else 503
    return JSONResponse(
        payload,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(
    request: Request,
    authorization: str | None = Header(default=None),
    x_metrics_token: str | None = Header(default=None),
) -> Response:
    """Prometheus text exposition, gated on METRICS_TOKEN."""
    if not _metrics_token_ok(authorization, x_metrics_token):
        # 404 rather than 401: an unauthenticated scraper learns nothing about
        # whether metrics exist here at all.
        return PlainTextResponse("not found\n", status_code=404)

    samples = COUNTERS.snapshot()
    samples[("downloader_uptime_seconds", ())] = round(time.time() - _PROCESS_START, 1)
    samples.update(await _redis_gauges())

    return PlainTextResponse(
        _render(samples),
        media_type="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )
