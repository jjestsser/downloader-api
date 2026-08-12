"""Single shared Redis client.

WHY a singleton with an explicit pool: Redis here is not a cache, it is the
enforcement point. Ticket replay (`SET NX`), per-IP quotas, the killswitch and
the spend counter all live in it, and each of those is on the hot path of every
request. A per-request client would mean a TCP+AUTH round trip per download and
would blow through Railway's connection limits under any real load.

Timeouts are short and deliberate: if Redis is slow we must fail the request
fast rather than pile up connections, because the fallback for "cannot check the
quota" is "refuse", never "allow".
"""

from __future__ import annotations

import asyncio
from typing import Final

from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import RedisError

from app.logging_conf import log
from app.settings import settings

#: Enough headroom for the API workers plus the arq worker on the same instance.
MAX_CONNECTIONS: Final[int] = 40
SOCKET_TIMEOUT_S: Final[float] = 2.0
CONNECT_TIMEOUT_S: Final[float] = 2.0
HEALTH_CHECK_INTERVAL_S: Final[int] = 30
PING_TIMEOUT_S: Final[float] = 1.0

_client: Redis | None = None
_pool: ConnectionPool | None = None
_lock: Final[asyncio.Lock] = asyncio.Lock()


def _build_pool() -> ConnectionPool:
    return ConnectionPool.from_url(
        settings.redis_url,
        max_connections=MAX_CONNECTIONS,
        decode_responses=True,
        socket_timeout=SOCKET_TIMEOUT_S,
        socket_connect_timeout=CONNECT_TIMEOUT_S,
        # Railway's proxy drops idle TCP connections; without this the first
        # command after a quiet period fails instead of transparently redialing.
        health_check_interval=HEALTH_CHECK_INTERVAL_S,
        retry_on_timeout=True,
    )


async def get_redis() -> Redis:
    """Return the process-wide client, creating it on first use.

    Double-checked under a lock so concurrent startup requests cannot each build
    a pool and leak all but one of them.
    """
    global _client, _pool
    if _client is not None:
        return _client
    async with _lock:
        if _client is None:
            _pool = _build_pool()
            _client = Redis(connection_pool=_pool)
            log.info("redis_pool_created", max_connections=MAX_CONNECTIONS)
    assert _client is not None
    return _client


async def ping(timeout_s: float = PING_TIMEOUT_S) -> bool:
    """Cheap liveness probe used by /readyz. Never raises."""
    try:
        client = await get_redis()
        async with asyncio.timeout(timeout_s):
            return bool(await client.ping())
    except (RedisError, OSError, asyncio.TimeoutError):
        return False
    except Exception:  # pragma: no cover - defensive, probes must not 500
        log.warning("redis_ping_unexpected_error", exc_info=True)
        return False


async def close_redis() -> None:
    """Close the client and its pool. Safe to call more than once."""
    global _client, _pool
    client, pool = _client, _pool
    _client, _pool = None, None
    if client is not None:
        try:
            # `aclose` on redis-py >= 5.0.1, `close` on older releases.
            closer = getattr(client, "aclose", None) or client.close
            await closer()
        except Exception:  # pragma: no cover - shutdown must not raise
            log.warning("redis_close_failed", exc_info=True)
    if pool is not None:
        try:
            await pool.disconnect(inuse_connections=True)
        except Exception:  # pragma: no cover
            log.warning("redis_pool_disconnect_failed", exc_info=True)
    if client is not None or pool is not None:
        log.info("redis_pool_closed")
