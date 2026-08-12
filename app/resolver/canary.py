"""Per-platform health canary.

WHY this exists: extractors do not fail loudly, they fail QUIETLY and all at
once. TikTok changes a signing parameter at 3am and every TikTok resolve starts
throwing the same extractor exception. Without a canary the first person to find
out is a user staring at "something went wrong", and the first person to
understand it is you, three days later, reading support mail.

So: resolve one known-public URL per platform every 30 minutes. Two consecutive
failures flip ``canary:{platform}`` to degraded, and the routes serve an honest
"TikTok is temporarily down, we're on it" instead of a stack trace. One success
flips it straight back to healthy - there is no penalty box, because a platform
that works should be usable immediately.

Two deliberate design choices:

* Two failures, not one. A single failure is very often the canary URL itself
  being deleted or geo-blocked, not the extractor breaking. Marking a healthy
  platform degraded is its own kind of outage.
* The Redis key carries a TTL of roughly three intervals. If the canary task
  itself dies, the state expires to "unknown" rather than sitting on a stale
  "healthy" forever. A missing canary must never be able to assert health.

Canary URLs are configurable per platform via ``CANARY_URL_<PLATFORM>`` env vars.
Only YouTube ships with a hardcoded default, because it is the one URL that has
been continuously public since 2005. Hardcoding guesses for the other platforms
would produce a canary that reports degradation caused by a deleted post - which
is worse than no canary at all. A platform with no configured URL is skipped and
reports "unknown", and unknown is treated as fine by callers.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import random
import time
from typing import Final

from app.errors import ApiError
from app.logging_conf import log
from app.redis_conn import get_redis
from app.resolver.platforms import SUPPORTED
from app.resolver.ytdlp import resolve

__all__ = [
    "run_canary",
    "run_canary_once",
    "platform_state",
    "all_platform_states",
    "CANARY_INTERVAL_S",
    "canary_urls",
]

#: 30 minutes, per the operating rules.
CANARY_INTERVAL_S: Final[int] = 30 * 60

#: Consecutive failures before we admit the platform is down.
DEGRADE_AFTER: Final[int] = 2

#: State expires if the canary stops running. Three intervals of slack absorbs
#: one slow cycle and a redeploy without flapping.
STATE_TTL_S: Final[int] = CANARY_INTERVAL_S * 3

#: Per-check ceiling. A canary must never be able to wedge the loop; the whole
#: sweep should finish in well under one interval.
CHECK_TIMEOUT_S: Final[int] = 45

#: Gap between platforms inside one sweep, so twelve extractions do not leave as
#: one burst that itself looks like abuse to the platforms.
STAGGER_S: Final[int] = 5

STATE_HEALTHY: Final[str] = "healthy"
STATE_DEGRADED: Final[str] = "degraded"
STATE_UNKNOWN: Final[str] = "unknown"

#: Public since April 2005 and structurally unlikely to disappear.
_DEFAULT_URLS: Final[dict[str, str]] = {
    "youtube": "https://www.youtube.com/watch?v=jNQXAC9IVRw",
}


def canary_urls() -> dict[str, str]:
    """Resolve the canary URL per platform from env, falling back to defaults.

    Read at call time rather than import time so an operator can add a canary URL
    with a Railway variable change and a restart, without a code deploy.
    """
    urls: dict[str, str] = {}
    for platform in SUPPORTED:
        env_value = os.environ.get(f"CANARY_URL_{platform.upper()}", "").strip()
        url = env_value or _DEFAULT_URLS.get(platform, "")
        if url:
            urls[platform] = url
    return urls


def _key(platform: str) -> str:
    return f"canary:{platform}"


async def platform_state(platform: str) -> str:
    """Current health of a platform: healthy, degraded, or unknown.

    Routes should reject with ``platform_degraded`` only on DEGRADED. Unknown
    means we have no evidence either way (no canary URL configured, or the canary
    has not run yet) and must be treated as usable - an unconfigured canary is
    not a reason to refuse a user's download.
    """
    state = await _read(platform)
    return state["state"]


async def all_platform_states() -> dict[str, str]:
    """Every platform's state, for /healthz, /metrics and the status banner."""
    return {platform: await platform_state(platform) for platform in SUPPORTED}


async def run_canary() -> None:
    """Forever-loop canary. Started as a background task from the app lifespan.

    Cancellation-safe: an ``asyncio.CancelledError`` propagates untouched so
    shutdown is immediate. Every other exception is swallowed and logged, because
    a canary that can kill itself is a canary that silently stops reporting.
    """
    log.info("canary.started", interval_s=CANARY_INTERVAL_S, platforms=sorted(canary_urls()))
    while True:
        try:
            await run_canary_once()
        except asyncio.CancelledError:
            log.info("canary.stopped", )
            raise
        except Exception as exc:  # noqa: BLE001 - the loop must outlive any single sweep
            log.error("canary.sweep_failed", err=type(exc).__name__)
        # Jitter so multiple replicas (and the platforms' own rate limiters) do
        # not see a synchronised thundering herd every half hour.
        await asyncio.sleep(CANARY_INTERVAL_S + random.uniform(-60, 60))


async def run_canary_once() -> dict[str, str]:
    """Run one sweep across all configured platforms and return the new states.

    Exposed separately so it can be triggered manually from an ops endpoint or a
    test without waiting out an interval.
    """
    results: dict[str, str] = {}
    for platform, url in canary_urls().items():
        if await _checked_recently(platform):
            # Another replica just did this one. Skipping keeps N replicas from
            # multiplying our extraction volume by N against every platform.
            results[platform] = await platform_state(platform)
            continue
        results[platform] = await _check(platform, url)
        await asyncio.sleep(STAGGER_S)
    return results


async def _check(platform: str, url: str) -> str:
    """Resolve one canary URL and record the outcome."""
    started = time.monotonic()
    try:
        await asyncio.wait_for(resolve(url, platform), timeout=CHECK_TIMEOUT_S)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - ApiError, TimeoutError and anything else are all "down"
        # ApiError carries the useful label (extractor_failed, platform_degraded);
        # everything else falls back to the exception class name.
        reason = getattr(exc, "code", None) if isinstance(exc, ApiError) else None
        return await _record_failure(platform, str(reason or type(exc).__name__))

    elapsed_ms = int((time.monotonic() - started) * 1000)
    return await _record_success(platform, elapsed_ms)


async def _record_success(platform: str, elapsed_ms: int) -> str:
    redis = await get_redis()
    now = int(time.time())
    previous = await _read(platform)

    await redis.hset(
        _key(platform),
        mapping={
            "state": STATE_HEALTHY,
            "fails": 0,
            "checked_at": now,
            "last_ok_at": now,
            "latency_ms": elapsed_ms,
            "last_error": "",
        },
    )
    await redis.expire(_key(platform), STATE_TTL_S)

    if previous["state"] == STATE_DEGRADED:
        log.warning("canary.recovered", platform=platform, latency_ms=elapsed_ms)
    else:
        log.info("canary.ok", platform=platform, latency_ms=elapsed_ms)
    return STATE_HEALTHY


async def _record_failure(platform: str, reason: str) -> str:
    redis = await get_redis()
    now = int(time.time())
    key = _key(platform)

    fails = int(await redis.hincrby(key, "fails", 1))
    state = STATE_DEGRADED if fails >= DEGRADE_AFTER else STATE_UNKNOWN

    await redis.hset(
        key,
        mapping={
            "state": state,
            "checked_at": now,
            "last_error": reason[:120],
        },
    )
    await redis.expire(key, STATE_TTL_S)

    if state == STATE_DEGRADED:
        log.error("canary.degraded", platform=platform, fails=fails, reason=reason[:120])
    else:
        log.warning("canary.failed", platform=platform, fails=fails, reason=reason[:120])
    return state


async def _checked_recently(platform: str) -> bool:
    """True if some replica checked this platform within half an interval.

    A cheap substitute for a distributed lock that stays inside the fixed Redis
    key contract: we do not need mutual exclusion, only to avoid every replica
    hammering the same twelve URLs at the same moment.
    """
    state = await _read(platform)
    checked_at = state["checked_at"]
    if not checked_at:
        return False
    return (int(time.time()) - int(checked_at)) < (CANARY_INTERVAL_S // 2)


async def _read(platform: str) -> dict[str, str | int]:
    redis = await get_redis()
    raw = await redis.hgetall(_key(platform)) or {}
    decoded: dict[str, str] = {}
    for field_name, value in raw.items():
        k = field_name.decode() if isinstance(field_name, bytes) else str(field_name)
        v = value.decode() if isinstance(value, bytes) else str(value)
        decoded[k] = v

    state = decoded.get("state", STATE_UNKNOWN)
    if state not in (STATE_HEALTHY, STATE_DEGRADED, STATE_UNKNOWN):
        state = STATE_UNKNOWN

    def _int(name: str) -> int:
        with contextlib.suppress(TypeError, ValueError):
            return int(decoded.get(name, 0) or 0)
        return 0

    return {
        "state": state,
        "fails": _int("fails"),
        "checked_at": _int("checked_at"),
        "last_ok_at": _int("last_ok_at"),
        "latency_ms": _int("latency_ms"),
        "last_error": decoded.get("last_error", ""),
    }
