"""Job submission and status, backed by arq.

## Why job state lives in our own Redis hash rather than arq's result store

arq records a result only once a job *finishes*. A client polling two seconds
after submitting needs an answer before that, and it needs a percentage while
the download runs — neither of which arq models. So the authoritative record is
a hash we own at `job:{id}:meta`, written at enqueue time and updated by the
worker as it progresses. arq stays responsible for the one thing it is good at:
getting the function onto a worker exactly once.

## Ownership

Every job carries the `ip_hash` of the ticket that created it. `job_status`
refuses to return a job to a different requester, and it raises `job_not_found`
rather than a distinct "forbidden" — a 403 would confirm the id exists, turning
job ids into an enumeration oracle.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Final

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from app.errors import ApiError
from app.logging_conf import log
from app.models import JobStatus
from app.redis_conn import get_redis
from app.settings import settings

#: Job metadata outlives the media itself so a late poll gets "expired", not a 404.
META_TTL_S: Final[int] = 24 * 3600

_META_KEY: Final[str] = "job:{job_id}:meta"

_pool: ArqRedis | None = None


def meta_key(job_id: str) -> str:
    return _META_KEY.format(job_id=job_id)


async def get_arq() -> ArqRedis:
    """Lazily-created arq pool, shared by the API process."""
    global _pool
    if _pool is None:
        _pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    return _pool


async def close_arq() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None


async def enqueue_download(payload: dict[str, Any]) -> str:
    """Queue a download and return its job id.

    The meta hash is written *before* the job is enqueued. Doing it the other
    way round leaves a window where the worker has already started and is
    writing progress into a key the API is about to overwrite with `queued`.
    """
    job_id = uuid.uuid4().hex
    payload = {**payload, "job_id": job_id}

    redis = await get_redis()
    await redis.hset(
        meta_key(job_id),
        mapping={
            "state": "queued",
            "progress": "0",
            "ip_hash": payload["ip_hash"],
            "platform": payload.get("platform", ""),
            "created_at": str(int(time.time())),
        },
    )
    await redis.expire(meta_key(job_id), META_TTL_S)

    pool = await get_arq()
    job = await pool.enqueue_job("download_job", payload, _job_id=job_id)
    if job is None:
        # arq returns None when a job with this id already exists. A fresh uuid4
        # colliding means something is very wrong; fail loudly rather than
        # handing back an id that points at someone else's work.
        await redis.delete(meta_key(job_id))
        raise ApiError("internal", "Could not queue this download. Try again.")

    log.info("job_enqueued", job_id=job_id, platform=payload.get("platform"))
    return job_id


async def job_status(job_id: str, ip_hash: str | None = None) -> JobStatus:
    """Read a job's current state.

    `ip_hash` is the requester's. When supplied it must match the creator's, or
    the job is reported as missing.
    """
    redis = await get_redis()
    meta: dict[str, str] = await redis.hgetall(meta_key(job_id))

    if not meta:
        raise ApiError("job_not_found")
    if ip_hash is not None and meta.get("ip_hash") != ip_hash:
        raise ApiError("job_not_found")

    expires_at = _as_int(meta.get("expires_at"))
    download_url = meta.get("download_url") or None

    # A presign that has already lapsed must not be handed out again.
    if download_url and expires_at and expires_at <= int(time.time()):
        download_url, expires_at = None, None

    return JobStatus(
        id=job_id,
        state=meta.get("state", "queued"),  # type: ignore[arg-type]
        progress=max(0, min(100, _as_int(meta.get("progress")) or 0)),
        error_code=meta.get("error_code") or None,
        download_url=download_url,
        expires_at=expires_at,
        # Withheld in production: it is a raw exception message and can name
        # paths, hosts and URL fragments. Everywhere else it is the difference
        # between diagnosing a deploy and guessing at one.
        error_detail=None if settings.is_production else (meta.get("error_detail") or None),
    )


async def set_state(job_id: str, **fields: Any) -> None:
    """Merge fields into a job's meta hash. Used by the worker."""
    redis = await get_redis()
    mapping = {k: str(v) for k, v in fields.items() if v is not None}
    if not mapping:
        return
    await redis.hset(meta_key(job_id), mapping=mapping)
    await redis.expire(meta_key(job_id), META_TTL_S)


def _as_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
