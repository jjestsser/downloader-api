"""yt-dlp metadata extraction and the direct-vs-worker delivery decision.

This module never downloads bytes. It runs ``extract_info(download=False)``,
turns yt-dlp's format dicts into our ``MediaFormat`` shape, and decides whether
the client can fetch the CDN URL itself (``delivery="direct"``, ~$0.10/1000) or
whether the bytes must pass through a worker (``delivery="job"``, ~$2/1000, up to
~$180/1000 for 1080p over residential proxies).

Two rules drive that decision and both must hold for a direct handoff:

  1. The platform is in ``DIRECT_HANDOFF`` - its CDN URLs are not IP-bound and
     not Referer-gated. Per-platform reasoning lives in ``platforms.py``.
  2. A SINGLE format carries both audio and video over plain HTTP(S). If the best
     rendition is adaptive (video-only + audio-only) or segmented (HLS/DASH), a
     browser cannot save it as one playable file, so muxing is required and
     muxing means ffmpeg and ffmpeg means the worker. This check is what makes
     the flag safe: Reddit is flagged direct but most v.redd.it posts still land
     on the worker path, correctly, because their audio is a separate file.

PRIVACY: we log SHA-256 URL hashes, never URLs. A hash lets us correlate a user's
error report with a log line; it does not build a record of who downloaded what.
That record has no product value and is the worst possible thing to be holding if
a legal request ever arrives. Do not "temporarily" log a URL to debug something.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Final, Literal

import httpx
import yt_dlp
from yt_dlp.utils import (
    DownloadError,
    ExtractorError,
    GeoRestrictedError,
    UnsupportedError,
)

from app.errors import ApiError
from app.logging_conf import log
from app.models import MediaFormat, ResolveResponse
from app.resolver.platforms import DIRECT_HANDOFF, SUPPORTED
from app.resolver.proxies import deescalate, escalate, proxy_for
from app.settings import settings

__all__ = ["YDL_BASE", "resolve", "url_hash"]


def _cache_dir() -> str:
    """yt-dlp's cache dir, on the only writable path in the container.

    WHY it matters: the cache holds extractor signature/nsig solutions. Without a
    persistent one, every single YouTube resolve re-derives the player challenge,
    which is both slow and a great way to get rate-limited. TMPDIR is /scratch in
    the container image; the tempfile fallback is only for local test runs.
    """
    base = os.environ.get("YTDLP_CACHE_DIR") or os.environ.get("TMPDIR") or "/scratch"
    path = Path(base) / "yt-dlp-cache"
    try:
        path.mkdir(parents=True, exist_ok=True)
        return str(path)
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "yt-dlp-cache"
        fallback.mkdir(parents=True, exist_ok=True)
        return str(fallback)


CACHE_DIR: Final[str] = _cache_dir()

#: Protocols a browser can save as a single file. Anything else (m3u8,
#: http_dash_segments, ism, rtmp) needs an assembler, i.e. the worker.
_PROGRESSIVE_PROTOCOLS: Final[frozenset[str]] = frozenset({"http", "https"})

#: Storyboards, thumbnails-as-formats and other non-media rows yt-dlp emits.
_JUNK_EXTS: Final[frozenset[str]] = frozenset({"mhtml", "none", ""})

_EXT_LABELS: Final[dict[str, str]] = {
    "mp4": "MP4",
    "m4a": "M4A",
    "webm": "WEBM",
    "mp3": "MP3",
    "opus": "OPUS",
    "ogg": "OGG",
    "mkv": "MKV",
    "mov": "MOV",
    "3gp": "3GP",
    "wav": "WAV",
    "flac": "FLAC",
}

#: Substrings that mean "the platform pushed back", as opposed to "this specific
#: video is gone". Only these trigger proxy escalation - see proxies.py for why
#: escalating on the wrong signal is expensive.
_BLOCKED_MARKERS: Final[tuple[str, ...]] = (
    "http error 403",
    "http error 429",
    "too many requests",
    "rate-limit",
    "rate limit",
    "sign in to confirm",
    "confirm you're not a bot",
    "captcha",
    "blocked",
    "forbidden",
    "temporarily blocked",
    "login required to access",
)

_NOT_AVAILABLE_MARKERS: Final[tuple[str, ...]] = (
    "video unavailable",
    "this video is private",
    "private video",
    "has been removed",
    "no longer available",
    "account has been",
    "post not found",
    "not found",
    "does not exist",
    "deleted",
)


class _YdlLogger:
    """Routes yt-dlp's chatter into our JSON logger, dropping anything URL-ish.

    WHY a custom logger rather than ``quiet``: quiet still lets warnings reach
    stderr unstructured, and yt-dlp messages routinely embed the full media URL
    plus signed CDN URLs. Everything here is scrubbed before it is emitted.
    """

    _URLISH = re.compile(r"https?://\S+", re.IGNORECASE)

    def _scrub(self, msg: str) -> str:
        return self._URLISH.sub("<url>", str(msg))[:500]

    def debug(self, msg: str) -> None:  # noqa: D102 - yt-dlp logger protocol
        return

    def info(self, msg: str) -> None:  # noqa: D102
        return

    # NOTE the keyword is `detail`, not `msg`. `log` is a LoggerAdapter whose
    # own first positional parameter is named `msg`, so passing `msg=` raised
    # "TypeError: LoggerAdapter.warning() got multiple values for argument
    # 'msg'" — from inside the error handler. Every yt-dlp failure therefore
    # became an opaque 500 that hid the real extractor error, which is the worst
    # possible place for a bug: it only fires when something else has already
    # gone wrong, and it destroys the evidence.
    def warning(self, msg: str) -> None:  # noqa: D102
        log.info("ytdlp.warning", detail=self._scrub(msg))

    def error(self, msg: str) -> None:  # noqa: D102
        log.warning("ytdlp.error", detail=self._scrub(msg))


def _duration_filter(info: dict[str, Any], *, incomplete: bool = False) -> str | None:
    """yt-dlp ``match_filter``: reject anything longer than MAX_DURATION_S.

    Returning a string tells yt-dlp to skip the item. This is a hard guard inside
    the extractor so a multi-hour item can never begin downloading even if a
    caller bypasses the explicit check in :func:`resolve`. Live streams have no
    duration and are unbounded by definition, so they are rejected here too.

    ``incomplete=True`` means yt-dlp is filtering before full metadata exists;
    we accept in that case rather than reject on missing data.
    """
    if incomplete:
        return None
    if info.get("is_live") or info.get("live_status") in ("is_live", "post_live"):
        return "live streams are not supported"
    duration = info.get("duration")
    if duration is None:
        return None
    try:
        seconds = int(float(duration))
    except (TypeError, ValueError):
        return None
    if seconds > settings.max_duration_s:
        return f"longer than {settings.max_duration_s}s"
    return None


#: Base yt-dlp options. Every consumer (resolve here, the download job) starts
#: from a copy of this dict and overrides only what it needs.
YDL_BASE: Final[dict[str, Any]] = {
    # One URL must never become N jobs. Belt (noplaylist) and braces
    # (playlist_items) - some extractors honour only one of them.
    "noplaylist": True,
    "playlist_items": "1",
    # Bounded network behaviour. Without an explicit socket timeout a wedged CDN
    # connection pins a worker slot until the process is killed.
    "socket_timeout": 15,
    "retries": 3,
    "extractor_retries": 2,
    "fragment_retries": 3,
    "file_access_retries": 2,
    # Hard ceilings. max_filesize is enforced by yt-dlp itself so an
    # underreported filesize cannot blow past the budget mid-download.
    "max_filesize": settings.max_filesize_bytes,
    "match_filter": _duration_filter,
    # Persistent so YouTube signature solutions survive a redeploy.
    "cachedir": CACHE_DIR,
    "quiet": True,
    "no_warnings": True,
    "noprogress": True,
    "logger": _YdlLogger(),
    # Never let a failure inside one entry be silently swallowed - we want the
    # exception so we can map it to a real error code.
    "ignoreerrors": False,
    "no_color": True,
    "call_home": False,
    "check_formats": False,
    # Do not touch the host netrc/cookie jar. This service is anonymous by
    # design; picking up an operator's session would be both a privacy leak and
    # an account-ban risk.
    "usenetrc": False,
    "cookiefile": None,
    "geo_bypass": True,
    "nocheckcertificate": False,
    "http_headers": {
        "Accept-Language": "en-US,en;q=0.9",
    },
}


def url_hash(url: str) -> str:
    """Stable short hash of a URL, for logs and metrics.

    The ONLY representation of a user's URL that is allowed to leave this
    process. See the module docstring.
    """
    return hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()[:16]


async def resolve(url: str, platform: str) -> ResolveResponse:
    """Extract metadata for one media URL and decide how it should be delivered.

    Raises ApiError with one of: playlist_rejected, video_too_long,
    file_too_large, unsupported_platform, platform_degraded, extractor_failed,
    internal.
    """
    if platform not in SUPPORTED:
        raise ApiError("unsupported_platform", detail=f"{platform} is not supported")

    uh = url_hash(url)
    opts: dict[str, Any] = dict(YDL_BASE)
    opts["skip_download"] = True

    proxy = await proxy_for(platform)
    if proxy:
        opts["proxy"] = proxy

    try:
        # yt-dlp is entirely synchronous and does blocking network I/O, so it
        # must never run on the event loop thread.
        info = await asyncio.to_thread(_extract, url, opts)
    except ApiError:
        raise
    except UnsupportedError as exc:
        log.info("resolve.unsupported", platform=platform, url_hash=uh)
        raise ApiError("unsupported_platform", detail="No extractor matched this URL") from exc
    except GeoRestrictedError as exc:
        raise ApiError("extractor_failed", detail="This media is geo-restricted") from exc
    except (DownloadError, ExtractorError) as exc:
        raise await _map_extractor_error(exc, platform, uh) from exc
    except Exception as exc:  # noqa: BLE001 - last line of defence, never leak a traceback
        log.error("resolve.unexpected", platform=platform, url_hash=uh, err=type(exc).__name__)
        raise ApiError("internal", detail="Resolver failed unexpectedly") from exc

    if info is None:
        # extract_info returns None when match_filter rejected the item.
        raise ApiError("video_too_long", detail=_too_long_detail())

    info = _unwrap(info, uh)
    _enforce_limits(info, uh)

    formats = _build_formats(info, platform)
    if not formats:
        raise ApiError("extractor_failed", detail="No downloadable formats were found")

    delivery = await _choose_delivery(platform, formats)

    # A clean extraction is the signal that resets the proxy failure counter.
    await deescalate(platform)

    log.info("resolve.ok", platform=platform, url_hash=uh, delivery=delivery, format_count=len(formats), duration_s=info.get("duration"))

    return ResolveResponse(
        platform=platform,
        title=_clean_title(info.get("title")),
        duration_s=_as_int(info.get("duration")),
        thumbnail=_pick_thumbnail(info),
        uploader=_clean_text(info.get("uploader") or info.get("channel") or info.get("uploader_id"), 120),
        formats=formats,
        delivery=delivery,
    )


def _extract(url: str, opts: dict[str, Any]) -> dict[str, Any] | None:
    """Blocking yt-dlp call. Runs on a worker thread, never the event loop."""
    with yt_dlp.YoutubeDL(opts) as ydl:
        return ydl.extract_info(url, download=False)


def _unwrap(info: dict[str, Any], uh: str) -> dict[str, Any]:
    """Collapse a playlist-shaped result, or reject it.

    Some extractors wrap a single video in a playlist envelope even with
    ``noplaylist``; that case is fine and we unwrap it. A genuine multi-entry
    result is rejected outright - see the noplaylist rule.
    """
    if info.get("_type") not in ("playlist", "multi_video"):
        return info

    entries = [e for e in (info.get("entries") or []) if e]
    if len(entries) == 1:
        return entries[0]

    log.info("resolve.playlist_rejected", url_hash=uh, entries=len(entries))
    raise ApiError("playlist_rejected", detail="That link points to a playlist or channel. Please paste a single video URL.")


def _enforce_limits(info: dict[str, Any], uh: str) -> None:
    """Explicit duration/size checks on top of ``match_filter``.

    The filter inside yt-dlp makes the item disappear; this turns the same
    condition into a specific, honest error code for the API consumer.
    """
    if info.get("is_live") or info.get("live_status") in ("is_live", "post_live"):
        raise ApiError("video_too_long", detail="Live streams are not supported.")

    duration = _as_int(info.get("duration"))
    if duration is not None and duration > settings.max_duration_s:
        log.info("resolve.too_long", url_hash=uh, duration_s=duration)
        raise ApiError("video_too_long", detail=_too_long_detail())

    # If EVERY format is over the size cap there is nothing we can serve. If only
    # some are, the oversized ones are dropped during mapping instead.
    sizes = [
        s
        for s in (_filesize(f) for f in (info.get("formats") or []))
        if s is not None
    ]
    cap = settings.max_filesize_bytes
    if sizes and min(sizes) > cap:
        raise ApiError("file_too_large", detail=f"Every available format is larger than {settings.max_filesize_mb}MB.")


def _build_formats(info: dict[str, Any], platform: str) -> list[MediaFormat]:
    """Map yt-dlp format dicts to MediaFormat, best-first, deduped and labelled."""
    raw_formats = info.get("formats")
    if not raw_formats:
        # Some extractors (many TikTok/IG responses) return a flat single-format
        # info dict with the url at the top level.
        raw_formats = [info] if info.get("url") else []

    scored: list[tuple[tuple, MediaFormat]] = []
    cap = settings.max_filesize_bytes

    for raw in raw_formats:
        if not isinstance(raw, dict):
            continue
        mapped = _map_format(raw, platform)
        if mapped is None:
            continue
        if mapped.filesize is not None and mapped.filesize > cap:
            continue
        scored.append((_sort_key(raw, mapped), mapped))

    scored.sort(key=lambda pair: pair[0])
    return _dedupe([m for _, m in scored])


def _map_format(raw: dict[str, Any], platform: str) -> MediaFormat | None:
    """Convert one yt-dlp format dict, or None if it is not real media."""
    url = raw.get("url")
    if not url:
        return None

    ext = str(raw.get("ext") or "").lower()
    if ext in _JUNK_EXTS:
        return None
    if str(raw.get("format_note") or "").lower() == "storyboard":
        return None

    # Codec presence, and the two traps yt-dlp lays here.
    #
    # 1. `None` and `"none"` mean different things. `"none"` is "this stream is
    #    definitively absent"; `None` is "not probed yet", which is normal for
    #    HLS and DASH manifests. Collapsing them with `or "none"` made every
    #    Loom format look like it contained no media at all, so `resolve()`
    #    returned an empty format list and the platform appeared broken.
    #
    # 2. `audio_ext` / `video_ext` do NOT indicate presence. For a *combined*
    #    format yt-dlp sets `video_ext` to the container and `audio_ext` to
    #    "none", because a merged file has no separate audio extension. Reading
    #    that as "no audio" labelled every TikTok format — all of which are
    #    h264+aac in one file — as "video only (we add the audio)", which would
    #    have sent every TikTok download through a pointless mux.
    #
    # The codec fields alone are authoritative. Unknown is treated as present:
    # a format we cannot classify is still real media, and dropping it loses the
    # platform entirely, whereas keeping it costs at worst one redundant mux.
    # Note the `is None` test comes FIRST and is not folded into the string
    # comparison: `str(None).lower()` is the string "none", so stringifying
    # before comparing silently re-merges the two cases this code exists to keep
    # apart. Unknown means present; only an explicit "none" means absent.
    vcodec = raw.get("vcodec")
    acodec = raw.get("acodec")
    has_video = vcodec is None or str(vcodec).lower() != "none"
    has_audio = acodec is None or str(acodec).lower() != "none"

    if not has_video and not has_audio:
        # Images, subtitle tracks and storyboard tiles all land here.
        return None

    height = _as_int(raw.get("height"))
    if height is None and has_video:
        height = _height_from_resolution(raw.get("resolution"))

    protocol = str(raw.get("protocol") or "").lower()
    progressive = protocol in _PROGRESSIVE_PROTOCOLS and str(url).startswith("http")

    # direct_url is populated ONLY for handoff platforms serving a progressive
    # file. For everything else it stays None so we never hand a client an
    # IP-bound googlevideo URL that will 403 on their machine - an intermittent
    # 403 in the browser is far worse for users than an honest job queue.
    direct_url = url if (platform in DIRECT_HANDOFF and progressive) else None

    return MediaFormat(
        format_id=str(raw.get("format_id") or ext or "unknown"),
        ext=ext,
        label=_label(raw, has_video=has_video, has_audio=has_audio, height=height, ext=ext),
        height=height,
        filesize=_filesize(raw),
        has_audio=has_audio,
        has_video=has_video,
        direct_url=direct_url,
    )


def _label(
    raw: dict[str, Any],
    *,
    has_video: bool,
    has_audio: bool,
    height: int | None,
    ext: str) -> str:
    """Human-readable format name. Users pick from these, so they must be plain."""
    pretty_ext = _EXT_LABELS.get(ext, ext.upper() or "FILE")

    if has_video:
        quality = f"{height}p" if height else str(raw.get("format_note") or "Video")
        label = f"{quality} {pretty_ext}"
        fps = _as_int(raw.get("fps"))
        if fps and fps >= 50:
            label += f" {fps}fps"
        if not _is_universal(raw):
            # A user choosing 720p HEVC over 540p H.264 should be choosing it,
            # not discovering it when the file will not open on their phone.
            vcodec = str(raw.get("vcodec") or "").lower()
            family = (
                "H.265"
                if vcodec.startswith(("hev", "h265", "hvc", "bytevc"))
                else "AV1"
                if vcodec.startswith("av01")
                else "VP9"
                if vcodec.startswith("vp9")
                else "this codec"
            )
            label += f" — {family}, may not play on all devices"
        if not has_audio:
            # Say it plainly: this one costs the user a wait while we mux.
            label += " — video only (we add the audio)"
        return label

    bitrate = raw.get("abr") or raw.get("tbr")
    if bitrate:
        try:
            return f"Audio only — {pretty_ext} {int(round(float(bitrate)))}kbps"
        except (TypeError, ValueError):
            pass
    return f"Audio only — {pretty_ext}"


#: Video codecs that play on every phone, browser and desktop player without
#: exception. Everything else is a compatibility gamble the user did not ask to
#: take. H.264 is 20 years old and universally hardware-decoded; H.265/HEVC is
#: fine on Apple and unreliable on Android, Windows and older browsers; VP9 and
#: AV1 are browser-first and patchy in native players.
_UNIVERSAL_VCODECS: Final[tuple[str, ...]] = ("h264", "avc1", "avc3")


def _is_universal(raw: dict[str, Any]) -> bool:
    """True when the video codec is known-compatible, or simply not known.

    Unknown gets the benefit of the doubt on purpose. yt-dlp leaves `vcodec`
    unset for HLS and DASH manifests it has not probed, and Loom's HLS renditions
    are h264 in practice — warning "may not play on all devices" about a stream
    that plays fine everywhere teaches users to ignore the warning, which is
    worse than not showing one. Only a codec we positively identify as H.265,
    VP9 or AV1 earns the caveat.
    """
    vcodec = raw.get("vcodec")
    if vcodec is None or str(vcodec).lower() in ("", "none"):
        return True
    return str(vcodec).lower().startswith(_UNIVERSAL_VCODECS)


def _sort_key(raw: dict[str, Any], mapped: MediaFormat) -> tuple:
    """Best-first ordering. Lower tuple sorts earlier.

    Priority: playable-as-is video, then **codec compatibility**, then
    resolution, then bitrate, then MP4 over WEBM.

    Compatibility outranks resolution deliberately, and it is the one ordering
    choice here worth defending. TikTok serves H.264 at 540p and H.265 at 720p;
    ranking purely by resolution hands every user an HEVC file that Apple plays
    and much of Android and Windows does not. A 540p video that plays beats a
    720p video that does not, and the higher-resolution option is still in the
    list one row down for anyone who wants it.
    """
    muxed = mapped.has_video and mapped.has_audio
    tbr = raw.get("tbr") or raw.get("vbr") or raw.get("abr") or 0
    try:
        tbr = float(tbr)
    except (TypeError, ValueError):
        tbr = 0.0
    return (
        0 if mapped.has_video else 1,
        0 if muxed else 1,
        0 if (not mapped.has_video or _is_universal(raw)) else 1,
        -(mapped.height or 0),
        -tbr,
        0 if mapped.ext in ("mp4", "m4a") else 1,
        mapped.format_id,
    )


def _dedupe(formats: list[MediaFormat]) -> list[MediaFormat]:
    """Keep the best entry per (kind, height, ext) and cap the list length.

    WHY: YouTube alone returns 30+ formats, most of them codec variants a person
    cannot meaningfully choose between. A dropdown of 30 rows is a worse product
    than a dropdown of 8, and the list is already sorted best-first so the first
    hit in each bucket is the one to keep.
    """
    seen: set[tuple] = set()
    out: list[MediaFormat] = []
    for f in formats:
        bucket = (f.has_video, f.has_audio, f.height, f.ext)
        if bucket in seen:
            continue
        seen.add(bucket)
        out.append(f)
        if len(out) >= 12:
            break
    return out


#: How long to wait for the CORS pre-check before giving up and using the worker.
_CORS_PROBE_TIMEOUT_S: Final[float] = 4.0


async def _cors_allows_download(url: str) -> bool:
    """Can a browser on our origin fetch these bytes and save them as a file?

    This is not a nicety, it is the difference between a download and a
    disappointment. The HTML `download` attribute is **ignored for cross-origin
    URLs**: `<a href="https://cdn.example/v.mp4" download>` navigates to the
    video and plays it in a tab. The only way a browser turns a third-party URL
    into a saved file is `fetch()` -> `blob()` -> object URL, and `fetch()` is
    subject to CORS. No `Access-Control-Allow-Origin`, no download.

    So a "direct" delivery decision is only honest if the CDN actually allows the
    cross-origin read. Measured rather than assumed: video.twimg.com reflects our
    origin back and works; most CDNs send nothing and would leave the user
    staring at a video player wondering where their file went.

    One HEAD request against a URL we are about to hand out. Cheap next to the
    alternative, which is telling the user it worked when it did not. On any
    error we return False and fall back to the worker — the slow path always
    produces a file, and that is the property we are protecting.
    """
    origin = settings.cors_origins[0] if settings.cors_origins else None
    if not origin:
        # Nothing configured to check against; be conservative.
        return False
    try:
        async with httpx.AsyncClient(timeout=_CORS_PROBE_TIMEOUT_S, follow_redirects=True) as client:
            resp = await client.head(url, headers={"Origin": origin, "Range": "bytes=0-0"})
    except Exception:
        return False

    allow = resp.headers.get("access-control-allow-origin", "")
    return allow == "*" or allow.rstrip("/") == origin.rstrip("/")


async def _choose_delivery(
    platform: str, formats: list[MediaFormat]
) -> Literal["direct", "job"]:
    """Direct only when the platform allows it, one file needs no muxing, AND
    the browser is actually permitted to save it."""
    if platform not in DIRECT_HANDOFF:
        return "job"
    for f in formats:
        if f.direct_url and f.has_audio and f.has_video:
            if await _cors_allows_download(f.direct_url):
                return "direct"
            log.info("cors_blocked_falling_back_to_job", platform=platform)
            return "job"
    return "job"


async def _map_extractor_error(exc: Exception, platform: str, uh: str) -> ApiError:
    """Translate a yt-dlp failure into an API error, escalating proxies if blocked.

    Only genuine block signals (403/429/bot-check) escalate. A deleted video is
    not evidence of blocking, and escalating on it would buy residential
    bandwidth at ~$3-10/GB to fix a problem that does not exist.
    """
    message = str(getattr(exc, "msg", None) or exc).lower()

    if any(marker in message for marker in _BLOCKED_MARKERS):
        await escalate(platform)
        log.warning("resolve.blocked", platform=platform, url_hash=uh)
        return ApiError("platform_degraded", detail=f"{SUPPORTED[platform].name} is blocking requests right now. Try again shortly.")

    if "playlist" in message:
        return ApiError("playlist_rejected", detail="That link points to a playlist. Please paste a single video URL.")

    if any(marker in message for marker in _NOT_AVAILABLE_MARKERS):
        return ApiError("extractor_failed", detail="That media is private, removed, or otherwise unavailable.")

    if "unsupported url" in message:
        return ApiError("unsupported_platform", detail="No extractor matched this URL")

    log.warning("resolve.extractor_failed", platform=platform, url_hash=uh)
    return ApiError("extractor_failed", detail=f"Could not read that {SUPPORTED[platform].name} link.")


def _too_long_detail() -> str:
    return (
        f"That media is longer than the {settings.max_duration_s // 60} minute limit."
    )


def _filesize(raw: dict[str, Any]) -> int | None:
    for key in ("filesize", "filesize_approx"):
        value = _as_int(raw.get(key))
        if value:
            return value
    return None


def _pick_thumbnail(info: dict[str, Any]) -> str | None:
    thumb = info.get("thumbnail")
    if isinstance(thumb, str) and thumb.startswith("http"):
        return thumb
    thumbs = info.get("thumbnails") or []
    for candidate in reversed(thumbs):
        if isinstance(candidate, dict):
            url = candidate.get("url")
            if isinstance(url, str) and url.startswith("http"):
                return url
    return None


def _clean_title(value: Any) -> str:
    return _clean_text(value, 300) or "Untitled"


def _clean_text(value: Any, limit: int) -> str | None:
    """Strip control characters and clamp length.

    Titles come straight from user-generated content on other platforms, so they
    can contain newlines, RTL overrides and unbounded length. Everything that
    crosses our API boundary gets flattened first.
    """
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch == " ").strip()
    if not cleaned:
        return None
    return cleaned[:limit]


def _height_from_resolution(resolution: Any) -> int | None:
    if not isinstance(resolution, str):
        return None
    match = re.search(r"(\d+)\s*[x×]\s*(\d+)", resolution)
    if match:
        return int(match.group(2))
    match = re.search(r"(\d+)p", resolution)
    return int(match.group(1)) if match else None


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None
