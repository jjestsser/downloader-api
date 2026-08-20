"""Per-IP-hash quotas, the global spend killswitch, and cost estimation.

WHY IPs are hashed and never stored raw
---------------------------------------
Rate limiting needs a stable per-client key; it does not need identity.  A raw
IP in Redis (or worse, in logs) is personal data under GDPR and is the single
most useful field to anyone who shows up with a subpoena asking "who downloaded
this".  A salted, truncated SHA-256 gives us the exact same bucketing behaviour
while making the store useless as an identity database: the salt is a runtime
secret that never leaves the process env, and 16 hex chars (64 bits) is plenty
to keep collisions negligible at our traffic while destroying the original.
Rotate IP_SALT and every historical bucket becomes unlinkable.

WHY spend is *estimated* instead of measured
--------------------------------------------
Railway bills on measured CPU/RAM/egress but exposes no realtime billing API we
can poll inside a request, and the invoice lands weeks after the money is gone.
A cost cap that depends on a monthly invoice is not a cap.  So we model it: each
job reports its wall-clock time and the bytes it actually moved, we multiply by
rate constants calibrated from the Railway pricing page (and from the proxy
vendor's per-GB price, which dominates everything else), and we accumulate the
result in `spend:{YYYYMMDD}`.  The estimate is deliberately pessimistic - it is
better to trip the killswitch at an imagined $50 than to discover a real $900
bill on the first day a scraper finds the endpoint.  Recalibrate the constants
below against a real invoice once there is one; the model only has to be right
to within a factor of ~2 to do its job.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Final

from app.errors import ApiError
from app.logging_conf import log
from app.redis_conn import get_redis
from app.settings import settings

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GIB: Final[int] = 1024**3

#: Length (in hex chars) of the truncated IP digest.  Must match the value used
#: by the Next.js ticket-minting route (contrib/mint-ticket.ts) exactly, or
#: every ticket will fail its ip_hash check.
IP_HASH_LEN: Final[int] = 16

#: Key prefixes.  Duplicated as literals nowhere else - build keys via helpers.
_RESOLVE_KEY: Final[str] = "quota:res:{ip_hash}:{day}"
_BYTES_KEY: Final[str] = "quota:bytes:{ip_hash}:{day}"
_SPEND_KEY: Final[str] = "spend:{day}"
KILLSWITCH_KEY: Final[str] = "killswitch:global"

#: Counters live one extra day beyond their nominal window so a request landing
#: microseconds before UTC midnight cannot resurrect a key with no TTL.
_COUNTER_TTL_S: Final[int] = 48 * 3600

# --- cost model -------------------------------------------------------------
# All values are micro-USD (1e-6 USD).  Integers only: floats accumulate error
# across thousands of INCRBY calls and Redis counters are integers anyway.

#: Railway container time for a worker doing an mux/download job.  ~$0.000008/s
#: at the 2 vCPU / 2 GB shape we run.  Covers CPU + RAM, not bandwidth.
WORKER_MICRO_USD_PER_SECOND: Final[int] = 8

#: Egress out of Railway (into R2, and for any bytes we serve ourselves).
#: R2 itself has zero egress fees, which is the entire reason it is in the
#: architecture, but the Railway -> R2 hop is still billed bandwidth.
EGRESS_MICRO_USD_PER_GIB: Final[int] = 100_000  # $0.10 / GiB

#: Datacenter proxy pool, priced per GB by the vendor.
DATACENTER_PROXY_MICRO_USD_PER_GIB: Final[int] = 60_000  # $0.06 / GiB

#: Residential proxy pool.  Three orders of magnitude more expensive than
#: everything else on this list, which is why 1080p YouTube video is not the
#: default and why this number exists as a named constant you cannot miss.
RESIDENTIAL_PROXY_MICRO_USD_PER_GIB: Final[int] = 3_000_000  # $3.00 / GiB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalise_ip(ip: str) -> str:
    """Canonicalise an address so both sides of the ticket hash the same string.

    MEASURED 2026-08-12, and this is why the function exists: the same browser on
    the same loopback connection was reported as ``::ffff:127.0.0.1`` by Node
    (which the Next.js minting route hashed) and as ``127.0.0.1`` by uvicorn
    (which this service hashed). Two spellings of one address, two different
    digests, and every single ticket rejected as ``ip_mismatch``.

    That is not a localhost quirk. Any hop that hands over an IPv4-mapped IPv6
    address — a dual-stack listener, some proxies, some container networks — can
    produce the same split in production, where the symptom would be a service
    that is 100% broken with a 401 that says nothing useful.

    The rules must stay byte-identical to ``clientIp``/``hashIp`` in
    ``src/app/api/tools/download-ticket/route.ts``:
      - trim, lowercase
      - strip ``[...]`` brackets from a bracketed IPv6 literal
      - strip a leading ``::ffff:`` when what follows looks like IPv4
    """
    cleaned = ip.strip().lower()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if cleaned.startswith("::ffff:"):
        candidate = cleaned[7:]
        # Only unwrap a real dotted-quad; "::ffff:1.2" is not one and is left be.
        parts = candidate.split(".")
        if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
            cleaned = candidate
    return cleaned


def hash_ip(ip: str) -> str:
    """Return a salted, truncated digest of ``ip``.

    The construction is ``sha256(normalise_ip(ip) + IP_SALT).hexdigest()[:16]``
    and it is a wire format, not an implementation detail: the Next.js minting
    route embeds the result in the ticket payload and this service recomputes it
    from the request's own peer address.  Change the ordering, the encoding, the
    normalisation or the truncation length on one side only and every ticket is
    rejected.

    An empty/unknown IP is hashed like any other string rather than special
    cased, so a request with no resolvable peer still lands in a single stable
    bucket instead of bypassing quotas entirely.
    """
    digest = sha256(f"{normalise_ip(ip)}{settings.ip_salt}".encode("utf-8")).hexdigest()
    return digest[:IP_HASH_LEN]


def _utc_day() -> str:
    """Quota windows are UTC calendar days, never local time.

    Using the container's local time would silently change every bucket
    boundary if a region moves, and would make two replicas in different
    regions disagree about which day it is.
    """
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _seconds_until_utc_midnight() -> int:
    now = datetime.now(timezone.utc)
    end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
    return max(int((end - now).total_seconds()), 1)


async def _incr_with_ttl(key: str, amount: int, ttl_s: int) -> int:
    """INCRBY ``key`` and guarantee it carries a TTL.

    The naive "if the counter came back as 1, set the expiry" pattern has a
    hole: the process can die (or the connection can drop) between the INCR and
    the EXPIRE, leaving an immortal counter that permanently bans that IP hash.
    So instead of trusting the returned value we read the actual TTL in the
    same round trip and repair it whenever Redis reports -1 (key exists, no
    expiry).  That is idempotent, costs nothing extra, and self-heals a key
    that a previous crash left without a TTL.
    """
    redis = await get_redis()
    pipe = redis.pipeline(transaction=True)
    pipe.incrby(key, amount)
    pipe.ttl(key)
    new_value, ttl = await pipe.execute()
    if ttl is None or int(ttl) < 0:
        await redis.expire(key, ttl_s)
    return int(new_value)


# ---------------------------------------------------------------------------
# Quotas
# ---------------------------------------------------------------------------


async def consume_resolve_quota(ip_hash: str) -> None:
    """Charge one metadata resolve against today's per-IP allowance.

    Callers must pass the ``ip_hash`` taken from the *verified ticket claim*,
    not one recomputed from an arbitrary header.  The ticket's hash was
    produced by the minting route from an IP the CDN observed and the client
    cannot forge; recomputing it from `X-Forwarded-For` at this layer would let
    a client mint themselves a fresh quota bucket per request.

    The counter is incremented before the limit is checked, so a client that
    keeps hammering after a 429 keeps digging: there is no refund path and no
    read-then-write race to exploit.
    """
    limit = int(settings.resolve_quota_per_day)
    if limit <= 0:
        return

    key = _RESOLVE_KEY.format(ip_hash=ip_hash, day=_utc_day())
    used = await _incr_with_ttl(key, 1, _COUNTER_TTL_S)
    if used > limit:
        log.warning(
            "quota_exceeded",
            extra={"kind": "resolve", "ip_hash": ip_hash, "used": used, "limit": limit},
        )
        raise ApiError(
            "quota_exceeded",
            detail=f"Daily limit of {limit} lookups reached. Try again tomorrow.",
        )


async def consume_bytes_quota(ip_hash: str, n: int) -> None:
    """Charge ``n`` transferred bytes against today's per-IP byte allowance.

    This is the quota that actually protects the wallet.  Resolve calls are
    cheap; bytes are not.  It is charged twice in a job's life: optimistically
    with the *expected* filesize before a worker download starts (so a client
    cannot queue twenty 500 MB jobs in parallel and only get billed once each
    finishes), and again with the true byte count on completion via
    :func:`record_spend`'s caller.
    """
    if n <= 0:
        return

    # `settings.bytes_quota_per_day` exists to do this conversion in one place.
    # The previous `int(bytes_quota_gb_per_day) * _GIB` truncated the float
    # first, so BYTES_QUOTA_GB_PER_DAY=0.5 became 0 — and the `<= 0` guard below
    # then disabled the quota entirely. Tightening the limit turned it off.
    limit_bytes = settings.bytes_quota_per_day
    if limit_bytes <= 0:
        return

    key = _BYTES_KEY.format(ip_hash=ip_hash, day=_utc_day())
    used = await _incr_with_ttl(key, int(n), _COUNTER_TTL_S)
    if used > limit_bytes:
        log.warning(
            "quota_exceeded",
            extra={
                "kind": "bytes",
                "ip_hash": ip_hash,
                "used_bytes": used,
                "limit_bytes": limit_bytes,
            },
        )
        raise ApiError(
            "quota_exceeded",
            detail=(
                f"Daily transfer limit of {settings.bytes_quota_gb_per_day} GB reached. "
                "Try again tomorrow."
            ),
        )


async def assert_bytes_budget_available(ip_hash: str) -> None:
    """Refuse a new job when today's byte allowance is already gone.

    :func:`consume_bytes_quota` is charged with the true size, which cannot be
    known until the file exists — so on its own it can refuse to *hand over* a
    download but never refuses to *pay for* one. Every job submitted after the
    counter passed the limit still pulled its full payload through the proxy,
    raised ``quota_exceeded``, and threw the file away. The refusal cost exactly
    as much as no quota at all, which is the one thing a spend control must not
    do.

    Checking the counter before the worker starts costs one Redis read and caps
    the overshoot at a single file instead of an unbounded number of them. It
    does not need an expected size, which is what made the pre-charge described
    in :func:`consume_bytes_quota` impossible to implement honestly: nothing at
    enqueue time knows how big the result will be, and a client-supplied guess
    is a client-controlled quota.

    Deliberately not a reservation. Two jobs starting at once can still both
    pass, so the true bound is `in-flight jobs x max filesize` rather than the
    daily limit exactly. Bounding that further is the concurrency cap's job, not
    this function's.
    """
    limit_bytes = settings.bytes_quota_per_day
    if limit_bytes <= 0:
        return

    redis = await get_redis()
    key = _BYTES_KEY.format(ip_hash=ip_hash, day=_utc_day())
    used = int(await redis.get(key) or 0)
    if used >= limit_bytes:
        log.warning(
            "quota_exceeded",
            extra={
                "kind": "bytes_precheck",
                "ip_hash": ip_hash,
                "used_bytes": used,
                "limit_bytes": limit_bytes,
            },
        )
        raise ApiError(
            "quota_exceeded",
            detail="You have used today's downloads from this connection.",
        )


async def quota_snapshot(ip_hash: str) -> dict[str, int]:
    """Read today's counters without charging anything (for /metrics and tests)."""
    redis = await get_redis()
    day = _utc_day()
    pipe = redis.pipeline(transaction=False)
    pipe.get(_RESOLVE_KEY.format(ip_hash=ip_hash, day=day))
    pipe.get(_BYTES_KEY.format(ip_hash=ip_hash, day=day))
    resolves, transferred = await pipe.execute()
    return {
        "resolves": int(resolves or 0),
        "bytes": int(transferred or 0),
    }


# ---------------------------------------------------------------------------
# Killswitch
# ---------------------------------------------------------------------------


async def check_killswitch() -> None:
    """Raise ``killswitch_active`` if the global brake is engaged.

    Called at the top of every money-spending route.  It is one Redis GET, it
    is the last line of defence between a viral link and a five-figure bill,
    and it must never be skipped for "cheap" endpoints - the direct-handoff
    path is cheap per call but unbounded in call rate.
    """
    try:
        redis = await get_redis()
        engaged = await redis.get(KILLSWITCH_KEY)
    except Exception:
        # Fail CLOSED. Redis is what enforces every quota and the spend cap, so
        # with it unreachable this service has no cost ceiling at all — and the
        # one thing worse than being down is being down *and* running up a bill.
        # Previously the ConnectionError escaped as an opaque 500; a 503 is both
        # honest and the correct signal for a client to back off.
        log.error("killswitch_check_failed", exc_info=True)
        raise ApiError(
            "killswitch_active",
            detail="The service is temporarily unavailable. Please try again shortly.",
        ) from None

    if engaged:
        raise ApiError(
            "killswitch_active",
            detail="The service is paused for today. Please try again tomorrow.",
        )


async def trip_killswitch(reason: str, ttl_s: int | None = None) -> None:
    """Engage the global brake.

    The TTL defaults to "until the next UTC midnight" so a spend-triggered stop
    clears itself exactly when the daily counter rolls over.  A killswitch that
    needs a human to un-set it turns a cost incident into an outage.
    """
    redis = await get_redis()
    ttl = ttl_s if ttl_s is not None else _seconds_until_utc_midnight() + 60
    await redis.set(KILLSWITCH_KEY, reason, ex=ttl)
    log.critical("killswitch_tripped", extra={"reason": reason, "ttl_s": ttl})


async def clear_killswitch() -> None:
    """Manual override for an operator who has fixed the underlying cause."""
    redis = await get_redis()
    await redis.delete(KILLSWITCH_KEY)
    log.warning("killswitch_cleared", extra={})


# ---------------------------------------------------------------------------
# Spend accounting
# ---------------------------------------------------------------------------


def estimate_job_micro_usd(
    wall_s: float,
    bytes_transferred: int,
    proxy_tier: str | None = None,
) -> int:
    """Model the cost of one worker job in micro-USD.

    ``proxy_tier`` is ``None`` (direct), ``"datacenter"`` or ``"residential"``.
    The residential term dominates by ~50x, which is exactly the signal the
    killswitch needs: a handful of proxied 1080p pulls should trip a daily cap
    long before thousands of cheap direct handoffs do.
    """
    gib = max(bytes_transferred, 0) / _GIB
    micro = int(max(wall_s, 0.0) * WORKER_MICRO_USD_PER_SECOND)
    micro += int(gib * EGRESS_MICRO_USD_PER_GIB)
    if proxy_tier == "residential":
        micro += int(gib * RESIDENTIAL_PROXY_MICRO_USD_PER_GIB)
    elif proxy_tier == "datacenter":
        micro += int(gib * DATACENTER_PROXY_MICRO_USD_PER_GIB)
    return micro


async def record_spend(micro_usd: int) -> None:
    """Accumulate estimated spend for today and trip the killswitch at the cap.

    Deliberately fire-and-forget from the caller's point of view: accounting
    must never fail a job that already succeeded, so the only thing that can
    happen here is a counter moving and, at the threshold, the brake engaging.
    """
    if micro_usd <= 0:
        return

    cap = int(settings.daily_spend_cap_micro_usd or 0)
    key = _SPEND_KEY.format(day=_utc_day())
    total = await _incr_with_ttl(key, int(micro_usd), _COUNTER_TTL_S)

    log.info(
        "spend_recorded",
        extra={"delta_micro_usd": int(micro_usd), "total_micro_usd": total, "cap_micro_usd": cap},
    )

    if cap > 0 and total >= cap:
        # Trip on >= rather than > so a cap of exactly N stops at N, and trip
        # unconditionally rather than only on the crossing edge: SET is
        # idempotent and refreshing the TTL on an already-tripped switch is
        # harmless, whereas missing the crossing (two workers finishing at
        # once, both reading a total past the cap) would not be.
        await trip_killswitch(f"daily_spend_cap total={total} cap={cap}")


async def current_spend_micro_usd() -> int:
    """Today's accumulated estimate, for the /metrics endpoint."""
    redis = await get_redis()
    raw = await redis.get(_SPEND_KEY.format(day=_utc_day()))
    return int(raw or 0)
