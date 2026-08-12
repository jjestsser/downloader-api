"""Per-platform proxy escalation, stored in Redis.

COST RATIONALE - read this before touching the thresholds.

    direct (no proxy)   $0        the only free option
    datacenter proxy    ~$0.50-2 / GB, often a flat monthly pool
    residential proxy   ~$3-10  / GB, metered, and it is metered on BOTH
                                 directions of a video download

A 1080p YouTube video is ~120MB. On residential that is roughly $0.36-1.20 for
ONE download, i.e. ~$180 per 1000 at the top of the range. Escalating a platform
that did not actually need residential - because of one transient 403, or because
somebody hammered a dead URL - is precisely how the monthly bill goes from $20 to
$2,000 without anybody noticing until the invoice lands.

So the ladder is deliberately asymmetric:

  * escalate SLOWLY: three *consecutive* blocked responses. Any success anywhere
    in between resets the counter to zero, so a flaky minute cannot promote a
    platform.
  * de-escalate on a CLOCK, not on a whim: only after 24 hours with no block at
    all do we step down one level. Stepping down eagerly causes a flap
    (down -> blocked -> up -> down) that costs more than staying put, because
    every flap burns a handful of full-price retries.
  * step ONE level at a time in both directions. Jumping none -> residential on
    a burst of 403s is the expensive failure mode.

State lives in one Redis hash per platform at ``proxy_strategy:{platform}`` (the
key name is fixed by the service contract), with fields:

    level          "none" | "datacenter" | "residential"
    fails          consecutive blocked responses at the current level
    last_block_at  unix seconds of the most recent block (drives de-escalation)
    changed_at     unix seconds of the most recent level change (for ops)

A hash rather than several keys because the contract fixes the key namespace, and
because level+counter must be read together to make a decision.
"""

from __future__ import annotations

import time
from typing import Final

from app.logging_conf import log
from app.redis_conn import get_redis
from app.settings import settings

__all__ = [
    "LEVELS",
    "proxy_for",
    "escalate",
    "deescalate",
    "current_level",
    "strategy_snapshot",
]

# Ordered cheapest-first. Index in this tuple *is* the escalation ladder.
LEVELS: Final[tuple[str, ...]] = ("none", "datacenter", "residential")

#: Consecutive blocked responses before we spend money. See module docstring.
ESCALATE_AFTER: Final[int] = 3

#: Seconds of no blocks before we step back down one rung.
DEESCALATE_AFTER_S: Final[int] = 24 * 60 * 60


def _key(platform: str) -> str:
    return f"proxy_strategy:{platform}"


def _proxy_url_for_level(level: str) -> str | None:
    """Map a ladder level to a configured proxy URL.

    Falls back DOWN the ladder when a level is not configured. WHY down and not
    up: an unconfigured residential proxy must never silently become "no proxy at
    all applied but we think we are protected" - but it must equally never
    escalate us into a level we have no credentials for. Falling back to the next
    cheapest configured option keeps requests flowing and keeps the bill bounded.
    """
    if level == "residential":
        return (
            settings.proxy_residential_url
            or settings.proxy_datacenter_url
            or None
        )
    if level == "datacenter":
        return settings.proxy_datacenter_url or None
    return None


async def current_level(platform: str) -> str:
    """Read the ladder level for a platform, defaulting to the free one."""
    redis = await get_redis()
    raw = await redis.hget(_key(platform), "level")
    level = raw.decode() if isinstance(raw, bytes) else raw
    return level if level in LEVELS else "none"


async def proxy_for(platform: str) -> str | None:
    """Return the proxy URL yt-dlp should use for this platform right now.

    None means "go direct", which is both the default and the state we want every
    platform to be in. Callers pass the result straight into the yt-dlp ``proxy``
    option; None simply means the option is omitted.
    """
    level = await current_level(platform)
    url = _proxy_url_for_level(level)
    if level != "none" and url is None:
        # Configured to escalate but nothing to escalate to. Say so loudly once
        # per request rather than failing mysteriously with the same 403s.
        log.warning("proxy.level_unconfigured", platform=platform, level=level)
    return url


async def escalate(platform: str) -> None:
    """Record one blocked (403/429) response and promote after three in a row.

    Call this from the extractor's error path, not from generic failures. A
    private video, a deleted post, or a network timeout is NOT evidence that we
    are being blocked, and treating it as such is how a platform ends up on
    residential for no reason.
    """
    redis = await get_redis()
    key = _key(platform)
    now = int(time.time())

    fails = int(await redis.hincrby(key, "fails", 1))
    await redis.hset(key, mapping={"last_block_at": now})

    if fails < ESCALATE_AFTER:
        log.info("proxy.block_recorded", platform=platform, fails=fails, threshold=ESCALATE_AFTER)
        return

    level = await current_level(platform)
    idx = LEVELS.index(level)
    if idx >= len(LEVELS) - 1:
        # Already at the top. Keep the counter pinned at the threshold so the
        # next block does not inflate it forever, and let the canary mark the
        # platform degraded instead - there is nothing left to buy.
        await redis.hset(key, mapping={"fails": ESCALATE_AFTER})
        log.warning("proxy.escalation_exhausted", platform=platform, level=level)
        return

    new_level = LEVELS[idx + 1]
    await redis.hset(
        key,
        mapping={"level": new_level, "fails": 0, "changed_at": now},
    )
    log.warning("proxy.escalated", platform=platform, from_level=level, to_level=new_level, cost_note="residential is ~$3-10/GB")


async def deescalate(platform: str) -> None:
    """Record a clean resolve and step down one level after 24h without blocks.

    Called on every successful extraction, so it is on the hot path: it does at
    most one HGETALL and one HSET. The consecutive-failure reset is the important
    half - it is what makes ESCALATE_AFTER mean "three in a row" rather than
    "three ever".
    """
    redis = await get_redis()
    key = _key(platform)
    state = await _read(key)
    now = int(time.time())

    if state["fails"]:
        await redis.hset(key, mapping={"fails": 0})

    level = state["level"]
    if level == "none":
        return

    last_block_at = state["last_block_at"]
    # No recorded block yet (e.g. level set by hand): treat the level change time
    # as the clock start so a manually pinned platform still decays.
    reference = last_block_at or state["changed_at"] or now
    if now - reference < DEESCALATE_AFTER_S:
        return

    new_level = LEVELS[LEVELS.index(level) - 1]
    await redis.hset(
        key,
        mapping={"level": new_level, "fails": 0, "changed_at": now},
    )
    log.info("proxy.deescalated", platform=platform, from_level=level, to_level=new_level, clean_for_s=now - reference)


async def strategy_snapshot() -> dict[str, dict[str, int | str]]:
    """Every platform's current ladder state, for /metrics and ops dashboards.

    Exposed because "which platforms are on residential right now" is the single
    question you want answered when the proxy invoice looks wrong.
    """
    from app.resolver.platforms import SUPPORTED  # local import: avoids a cycle

    out: dict[str, dict[str, int | str]] = {}
    for platform in SUPPORTED:
        out[platform] = await _read(_key(platform))  # type: ignore[assignment]
    return out


async def _read(key: str) -> dict:
    """Read and coerce the strategy hash, tolerating a missing or partial key."""
    redis = await get_redis()
    raw = await redis.hgetall(key) or {}
    decoded: dict[str, str] = {}
    for field_name, value in raw.items():
        k = field_name.decode() if isinstance(field_name, bytes) else str(field_name)
        v = value.decode() if isinstance(value, bytes) else str(value)
        decoded[k] = v

    level = decoded.get("level", "none")
    if level not in LEVELS:
        level = "none"
    return {
        "level": level,
        "fails": _to_int(decoded.get("fails")),
        "last_block_at": _to_int(decoded.get("last_block_at")),
        "changed_at": _to_int(decoded.get("changed_at")),
    }


def _to_int(value: str | None) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0
