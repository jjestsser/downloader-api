"""arq worker configuration.

## Why yt-dlp self-updates on startup

Extractors rot. Platforms rotate signature ciphers, tokens and player code
continuously, and yt-dlp ships fixes within days — so a version pinned at build
time works for roughly a week and then starts failing on one platform at a
time, quietly, with the service still returning 200 on `/healthz`. Updating on
worker startup means every deploy and every restart picks up the current
extractors, and the Railway cron that restarts this service daily turns that
into a daily refresh.

The tradeoff is real and worth stating: an upstream regression reaches
production without review. The health canary is the counterweight — it notices a
platform breaking within 30 minutes and marks it degraded, which is a far
better failure mode than a pinned version that breaks everything at once six
weeks from now.

## Concurrency

`max_jobs` is the global concurrency cap, not a per-user one. Each concurrent
job holds an ffmpeg process and its working set in `/scratch`, so this number is
bounded by container memory and disk, not by CPU.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from typing import Any, Final

from arq.connections import RedisSettings

from app.jobs.download import SCRATCH, download_job
from app.logging_conf import log, setup_logging
from app.settings import settings

#: Concurrent downloads per worker container.
MAX_JOBS: Final[int] = 8

#: Hard ceiling on one download. Longer than the slowest legitimate 1080p pull,
#: short enough that a wedged extractor frees its slot the same minute.
JOB_TIMEOUT_S: Final[int] = 900

#: arq keeps results this long; our own meta hash is the client-facing record.
KEEP_RESULT_S: Final[int] = 3600


async def startup(ctx: dict[str, Any]) -> None:
    setup_logging()
    _clear_scratch()
    log.info("worker_started", max_jobs=MAX_JOBS, environment=settings.environment)


async def shutdown(ctx: dict[str, Any]) -> None:
    log.info("worker_stopping")


# `_update_ytdlp` used to live here, running `pip install --upgrade yt-dlp` at
# worker startup. It could never have worked, in two independent ways:
#
#   * the venv is built by `uv sync`, which does not install pip — every boot
#     logged `ytdlp_update_failed: /opt/venv/bin/python: No module named pip`
#   * the Dockerfile runs `chmod -R a-w /opt/venv`, deliberately, so nothing at
#     runtime can write to what it executes
#
# The second one is a security property worth keeping, which makes in-place
# upgrading the wrong idea rather than a broken one. Removing the function
# instead of fixing it.
#
# Updating happens at image build: pyproject pins `yt-dlp[default]>=2025.6.30`
# with no upper bound and there is no lockfile, so every rebuild resolves the
# current release. Extractors rot in days, so the rebuild wants to be on a
# schedule rather than on a push.


def _clear_scratch() -> None:
    """Drop anything a previous container left behind.

    Railway restarts do not necessarily clear the volume, and a crashed job's
    half-downloaded 400 MB file is pure cost until something deletes it.
    """
    if not SCRATCH.exists():
        SCRATCH.mkdir(parents=True, exist_ok=True)
        return
    for child in SCRATCH.iterdir():
        shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink(
            missing_ok=True
        )


class WorkerSettings:
    """Entrypoint for `arq app.jobs.worker.WorkerSettings`."""

    functions = [download_job]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = MAX_JOBS
    job_timeout = JOB_TIMEOUT_S
    keep_result = KEEP_RESULT_S
    max_tries = 1  # A failed extraction fails the same way on retry, at double the cost.

    @staticmethod
    def redis_settings() -> RedisSettings:
        return RedisSettings.from_dsn(settings.redis_url)


# arq reads `redis_settings` as an attribute, not a callable, when it is not a
# staticmethod-returning-descriptor. Bind the concrete value at import.
WorkerSettings.redis_settings = RedisSettings.from_dsn(settings.redis_url)  # type: ignore[assignment]
