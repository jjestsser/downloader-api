"""The worker-path download job.

## Why yt-dlp is allowed to drive ffmpeg instead of us

The obvious reading of "never shell out with user input" is to run ffmpeg
ourselves with a hand-built argv. That would be worse. yt-dlp already invokes
ffmpeg through `subprocess` with a list — never a shell string — and it knows
which of the dozen container/codec combinations actually need remuxing versus a
straight copy. Re-implementing that badly is how you end up with a mux step that
silently transcodes 1080p on a CPU you are paying for by the second.

What we keep control of: the format selector is validated upstream
(`JobCreateRequest._safe_format_id`), the output template can only ever land
inside this job's own scratch directory, and the whole thing runs under an arq
`job_timeout` so a wedged ffmpeg cannot pin a worker slot forever.

## Progress

yt-dlp's progress hook is synchronous and runs on the worker thread, so it
cannot await a Redis write. It hands percentages to the event loop with
`run_coroutine_threadsafe` against the loop captured before `to_thread`, and
throttles to one write per second — a 300 MB file fires the hook hundreds of
times and none of that belongs in Redis.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Final

import yt_dlp

from app.errors import ApiError
from app.jobs.queue import set_state
from app.logging_conf import log
from app.resolver.proxies import current_level, deescalate, escalate, proxy_for
from app.resolver.ytdlp import YDL_BASE, url_hash
from app.security.quotas import consume_bytes_quota, estimate_job_micro_usd, record_spend
from app.settings import settings
from app.storage import r2

#: The one writable directory in the container. The Dockerfile also points
#: TMPDIR here, so every library's temp file lands where the cleanup runs.
#: Read through `settings` so a `.env` override actually applies — reading
#: `os.environ` here meant SCRATCH_DIR in .env was ignored and the worker died
#: on a read-only `/scratch` when run outside the container.
SCRATCH: Final[Path] = Path(settings.scratch_dir)

#: One Redis write per second of download, at most.
_PROGRESS_INTERVAL_S: Final[float] = 1.0

#: yt-dlp reports bytes as it goes; we only trust the file on disk for billing.
_AUDIO_CODEC: Final[str] = "m4a"


async def download_job(ctx: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Download one item, put it in R2, and hand back a presigned URL."""
    job_id: str = payload["job_id"]
    url: str = payload["url"]
    platform: str = payload["platform"]
    fmt: str = payload["format_id"]
    mode: str = payload.get("mode", "video")
    ip_hash: str = payload["ip_hash"]

    uh = url_hash(url)
    workdir = SCRATCH / job_id
    started = time.monotonic()
    proxy_tier = await current_level(platform)
    key: str | None = None

    try:
        workdir.mkdir(parents=True, exist_ok=True)
        await set_state(job_id, state="running", progress=1)

        loop = asyncio.get_running_loop()
        proxy = await proxy_for(platform)
        opts = _build_opts(workdir, fmt, mode, proxy, job_id, loop)

        info = await asyncio.to_thread(_run_download, url, opts)
        produced = _pick_output(workdir)
        if produced is None:
            raise ApiError("extractor_failed", "The download finished but produced no file.")

        size = produced.stat().st_size
        if size > settings.max_filesize_bytes:
            raise ApiError("file_too_large")

        # Billed against the ticket holder, after the fact: we cannot know the
        # true size until the file exists, and refusing here is kinder than
        # refusing a 400 MB download at 99%.
        await consume_bytes_quota(ip_hash, size)

        await set_state(job_id, progress=92)
        key = f"{job_id}/{_safe_name(info, produced)}"
        await r2.upload(produced, key)

        expires_at = int(time.time()) + settings.result_ttl_s
        download_url = r2.presign(key, settings.result_ttl_s)

        await set_state(
            job_id,
            state="done",
            progress=100,
            download_url=download_url,
            expires_at=expires_at,
            r2_key=key,
        )
        await deescalate(platform)

        wall = time.monotonic() - started
        await record_spend(estimate_job_micro_usd(wall, size, proxy_tier))
        log.info(
            "job_done",
            job_id=job_id,
            platform=platform,
            url_hash=uh,
            bytes=size,
            wall_s=round(wall, 2),
            proxy_tier=proxy_tier,
        )
        return {"state": "done", "bytes": size}

    except ApiError as exc:
        await _fail(job_id, exc.code)
        log.warning("job_failed", job_id=job_id, platform=platform, url_hash=uh, code=exc.code)
        return {"state": "failed", "error_code": exc.code}

    except yt_dlp.utils.DownloadError as exc:
        # 403/429 from the platform is the signal the proxy tier is too low.
        text = str(exc).lower()
        if "403" in text or "429" in text or "sign in" in text:
            await escalate(platform)
        await _fail(job_id, "extractor_failed")
        log.warning("job_extractor_failed", job_id=job_id, platform=platform, url_hash=uh)
        return {"state": "failed", "error_code": "extractor_failed"}

    except Exception:
        await _fail(job_id, "internal")
        log.exception("job_crashed", job_id=job_id, platform=platform, url_hash=uh)
        return {"state": "failed", "error_code": "internal"}

    finally:
        # The input is deleted immediately and unconditionally. Only the R2 copy
        # survives, and only until its lifecycle rule expires it.
        shutil.rmtree(workdir, ignore_errors=True)


def _build_opts(
    workdir: Path,
    fmt: str,
    mode: str,
    proxy: str | None,
    job_id: str,
    loop: asyncio.AbstractEventLoop,
) -> dict[str, Any]:
    """yt-dlp options for one job, derived from the shared resolve baseline."""
    opts: dict[str, Any] = {
        **YDL_BASE,
        # `outtmpl` MUST be relative when `paths.home` is set — yt-dlp joins the
        # two. An absolute template here produced /scratch/{job}/scratch/{job}/f.mp4,
        # so `_pick_output(workdir)` found nothing and every worker download failed
        # *after* paying for the bytes. Caught by an end-to-end run, not by tests.
        "outtmpl": "%(id)s.%(ext)s",
        "paths": {"home": str(workdir), "temp": str(workdir)},
        "progress_hooks": [_progress_hook(job_id, loop)],
        "noprogress": True,
        "overwrites": True,
    }

    if mode == "audio":
        # Audio-only is the YouTube default because 1080p through a residential
        # proxy is ~$180/1000 downloads against ~$20 for m4a.
        opts["format"] = f"{fmt}/bestaudio/best"
        opts["postprocessors"] = [
            {
                "key": "FFmpegExtractAudio",
                "preferredcodec": _AUDIO_CODEC,
                "preferredquality": "0",
            }
        ]
    else:
        # Format selection, in priority order:
        #   1. the exact format the user picked, muxed with the best m4a audio
        #   2. that format alone, if it already carries audio
        #   3. any mp4/m4a pair            <- the compatibility fallback
        #   4. anything at all
        #
        # Step 3 exists because of a real failure: a Loom video resolved to VP9
        # video + Opus audio, and `merge_output_format: "mp4"` dutifully wrapped
        # them in a .mp4 the user's player would refuse. The extension promised
        # something the codecs could not deliver. Preferring an mp4/m4a pair
        # first means the common path produces h264+aac, which plays on every
        # phone, browser and desktop player without exception.
        opts["format"] = (
            f"{fmt}+bestaudio[ext=m4a]/{fmt}+bestaudio/{fmt}"
            "/bv*[ext=mp4]+ba[ext=m4a]/b[ext=mp4]/bv*+ba/b"
        )
        opts["merge_output_format"] = "mp4"
        # Last-resort safety net: if the muxed result still is not something a
        # normal player accepts, remux the container. This is a stream copy, not
        # a re-encode, so it costs no meaningful CPU.
        opts["postprocessors"] = [{"key": "FFmpegVideoRemuxer", "preferedformat": "mp4"}]

    if proxy:
        opts["proxy"] = proxy

    return opts


def _progress_hook(job_id: str, loop: asyncio.AbstractEventLoop):
    """Build a synchronous hook that pushes throttled progress to Redis."""
    last = {"at": 0.0}

    def hook(status: dict[str, Any]) -> None:
        if status.get("status") != "downloading":
            return
        now = time.monotonic()
        if now - last["at"] < _PROGRESS_INTERVAL_S:
            return
        last["at"] = now

        total = status.get("total_bytes") or status.get("total_bytes_estimate")
        done = status.get("downloaded_bytes") or 0
        if not total:
            return
        # 5..90 is reserved for the transfer; upload and finalise own the rest.
        pct = 5 + int((done / total) * 85)

        fut: Future[Any] = asyncio.run_coroutine_threadsafe(
            set_state(job_id, progress=min(90, pct)), loop
        )
        # Never let a Redis hiccup kill an otherwise healthy download.
        fut.add_done_callback(lambda f: f.exception())

    return hook


def _run_download(url: str, opts: dict[str, Any]) -> dict[str, Any]:
    """Blocking yt-dlp call. Always invoked through `asyncio.to_thread`."""
    with yt_dlp.YoutubeDL(opts) as ydl:
        return ydl.extract_info(url, download=True) or {}


def _pick_output(workdir: Path) -> Path | None:
    """The largest regular file left in the job directory after post-processing.

    yt-dlp leaves the merged result alongside its parts often enough that
    "newest" is unreliable; the muxed output is always the biggest.
    """
    files = [p for p in workdir.iterdir() if p.is_file() and not p.name.endswith(".part")]
    return max(files, key=lambda p: p.stat().st_size) if files else None


def _safe_name(info: dict[str, Any], produced: Path) -> str:
    """An object key that cannot escape its prefix or leak a title verbatim."""
    ext = produced.suffix.lstrip(".") or "bin"
    stem = str(info.get("id") or produced.stem)[:64]
    cleaned = "".join(ch for ch in stem if ch.isalnum() or ch in "-_") or "media"
    return f"{cleaned}.{ext}"


async def _fail(job_id: str, code: str) -> None:
    await set_state(job_id, state="failed", error_code=code, progress=0)
