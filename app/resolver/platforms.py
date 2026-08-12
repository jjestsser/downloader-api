"""Platform detection and the direct-CDN-handoff policy table.

WHY this module is the economic centre of the service: the single most expensive
decision we make per request is whether bytes flow through our worker. A platform
in ``DIRECT_HANDOFF`` costs roughly $0.10 per 1000 downloads because we only move
a JSON blob; the same platform routed through the worker costs ~$2 per 1000, and
~$180 per 1000 if it needs residential proxies at 1080p. So `direct_handoff` is
not a capability flag, it is a budget flag, and every entry below carries the
reason it was set the way it was.

The rule of thumb behind each decision: a CDN URL is client-fetchable when it is
signed against *time* (or nothing at all). It is NOT client-fetchable when it is
signed against the *requesting IP*, gated on a Referer/Origin header the browser
will not send cross-origin, or only published as segmented HLS/DASH that a
browser cannot save as one file. Those three cases force the worker path.

Detection deliberately requires a URL that points at a specific piece of media.
A bare profile or channel URL must NOT resolve to a platform - it should fall
through to ``unsupported_platform`` (or ``playlist_rejected``) rather than hand
yt-dlp something that expands into hundreds of entries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Literal, Pattern
from urllib.parse import urlsplit

__all__ = [
    "PlatformSpec",
    "SUPPORTED",
    "DIRECT_HANDOFF",
    "detect_platform",
    "is_playlist_url",
    "normalize_url",
]

# Anything longer than this is not a real media URL; it is someone probing us.
# Bounding it before we run a dozen regexes is cheap insurance against ReDoS-ish
# pathological input.
MAX_URL_LEN: Final[int] = 2048

# Optional subdomain chain: matches "m.", "vm.", "mobile.", "www2." and multi-label
# hosts, while still refusing look-alikes such as "nottiktok.com" (the group can
# only match if it ends in a literal dot, which "not" does not).
SUB: Final[str] = r"(?:[a-z0-9.-]+\.)?"

# Video-id boundary: stops "youtu.be/AAAAAAAAAAAAAAAA" (16 chars) from matching an
# 11-char id pattern by prefix.
END: Final[str] = r"(?![\w-])"


def _rx(*patterns: str) -> tuple[Pattern[str], ...]:
    """Compile host+path patterns case-insensitively, anchored at the start."""
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


@dataclass(frozen=True, slots=True)
class PlatformSpec:
    """One supported platform and the policy attached to it.

    Attributes:
        name: Human-facing name, used verbatim in user-visible copy.
        patterns: Compiled regexes matched against the *normalised* subject
            (``host + path [+ "?" + query]``, lowercased host, ``www.`` stripped).
        direct_handoff: True when the CDN URL is usually fetchable by the
            end-user's browser, so we can move zero bytes. See module docstring.
        default_mode: What the UI should preselect. YouTube defaults to audio
            because 1080p YouTube over residential proxies is the one path that
            can genuinely run up a four-figure bill.
        notes: WHY the flag above is set the way it is. Read this before you
            flip a platform into DIRECT_HANDOFF.
    """

    name: str
    patterns: tuple[Pattern[str], ...]
    direct_handoff: bool
    default_mode: Literal["video", "audio"] = "video"
    notes: str = field(default="")


SUPPORTED: Final[dict[str, PlatformSpec]] = {
    "tiktok": PlatformSpec(
        name="TikTok",
        patterns=_rx(
            SUB + r"tiktok\.com/@[\w.\-]+/(?:video|photo)/\d+",
            SUB + r"tiktok\.com/t/[\w-]+",
            r"(?:vm|vt|vr)\.tiktok\.com/[\w-]+",
            SUB + r"tiktok\.com/v/\d+",
            SUB + r"tiktok\.com/embed/v2/\d+",
        ),
        # MEASURED 2026-08-12, and it disproved the original assumption.
        #
        # The claim used to be that TikTok's play address is merely time-signed,
        # making it the ideal direct handoff. It is not. Resolving three real
        # videos and probing the returned CDN URL on v16-webapp-prime.tiktok.com:
        #
        #   bare request                         -> 403
        #   full yt-dlp headers, no cookies      -> 403
        #   same headers + session cookies       -> 206 OK
        #
        # The URL is bound to the session cookies (ttwid, msToken, _waftokenid,
        # tt_chain_token) that yt-dlp earns by solving a JS challenge. A browser
        # on our origin cannot supply them: they belong to tiktok.com, `Cookie`
        # and `Referer` are forbidden headers that the browser controls, and CORS
        # would block reading the response anyway.
        #
        # So TikTok costs the worker path (~$2/1000), not the handoff path
        # (~$0.10/1000). cobalt reaching the same conclusion independently — it
        # always tunnels TikTok while redirecting for Facebook and Instagram — is
        # corroboration, not coincidence.
        direct_handoff=False,
        default_mode="video",
        notes=(
            "Cookie-bound CDN URLs; see the measurement above. Must go through the "
            "worker. Photo/slideshow posts additionally have no video stream at "
            "all; resolve() drops them to audio-only or empty formats."
        ),
    ),
    "instagram": PlatformSpec(
        name="Instagram",
        patterns=_rx(
            SUB + r"instagram\.com/(?:p|reel|reels|tv)/[\w-]+",
            SUB + r"instagram\.com/[\w.\-]+/(?:p|reel|reels|tv)/[\w-]+",
            SUB + r"instagram\.com/stories/[\w.\-]+/\d+",
            r"instagr\.am/(?:p|reel|reels|tv)/[\w-]+",
        ),
        # MEASURED 2026-08-12: bare fetch 206, ffprobe found video only. Instagram
        # serves split streams, so a single URL yields silent video. Separately,
        # anonymous resolution is now unreliable without cookies — expect
        # extractor failures independent of this flag.
        direct_handoff=False,
        default_mode="video",
        notes=(
            "*.cdninstagram.com / *.fbcdn.net URLs are expiry-signed and bare-fetchable "
            "(measured 206), but Instagram publishes video and audio as separate "
            "streams, so one URL yields silent video and a mux is mandatory. "
            "Anonymous resolution is also unreliable in 2026 — logged-out clients get "
            "a metadata shell with no media — so cookies may be required to resolve at "
            "all. A failure here is usually the login wall, not a broken extractor."
        ),
    ),
    "facebook": PlatformSpec(
        name="Facebook",
        patterns=_rx(
            SUB + r"facebook\.com/[\w.\-]+/videos?/\d+",
            SUB + r"facebook\.com/watch/?\?(?:[^#]*&)?v=\d+",
            SUB + r"facebook\.com/reel/\d+",
            SUB + r"facebook\.com/video\.php\?(?:[^#]*&)?v=\d+",
            SUB + r"facebook\.com/story\.php\?",
            SUB + r"facebook\.com/share/[rv]/[\w-]+",
            r"fb\.watch/[\w-]+",
        ),
        # MEASURED 2026-08-12: bare fetch 206, ffprobe found video only. Split
        # streams, mux required. Anonymous access to public Reels does still work.
        direct_handoff=False,
        default_mode="video",
        notes=(
            "Same fbcdn edge as Instagram: bare-fetchable (measured 206) but split "
            "video/audio, so the worker must mux. Anonymous access to public Page "
            "videos and Reels does still work, which makes Facebook the most reliably "
            "testable of the Meta platforms."
        ),
    ),
    "twitter": PlatformSpec(
        name="X (Twitter)",
        patterns=_rx(
            SUB + r"(?:twitter|x)\.com/[\w]{1,20}/status(?:es)?/\d+",
            SUB + r"(?:twitter|x)\.com/i/(?:status|web/status(?:es)?)/\d+",
            SUB + r"(?:twitter|x)\.com/i/broadcasts/[\w-]+",
        ),
        direct_handoff=True,
        default_mode="video",
        notes=(
            "video.twimg.com serves unsigned, publicly cacheable progressive MP4 for "
            "ordinary tweet video - the cleanest direct handoff of the whole set. "
            "Live Spaces/broadcasts are HLS and will be routed to the worker by the "
            "protocol check. We accept both twitter.com and x.com because users paste "
            "both and the redirect costs an extra round trip we do not need to make."
        ),
    ),
    "reddit": PlatformSpec(
        name="Reddit",
        patterns=_rx(
            SUB + r"reddit\.com/r/[\w-]+/comments/[\w]+",
            SUB + r"reddit\.com/r/[\w-]+/s/[\w]+",
            SUB + r"reddit\.com/(?:user|u)/[\w.\-]+/comments/[\w]+",
            SUB + r"reddit\.com/comments/[\w]+",
            r"redd\.it/[\w]+",
            r"v\.redd\.it/[\w]+",
        ),
        # MEASURED 2026-08-12: bare cookie-less fetch of the best format returned
        # 206, but ffprobe on the bytes found a VIDEO STREAM ONLY. Reddit serves
        # DASH video and audio separately, so one URL handed to a browser is a
        # silent clip. Access is not the blocker; the mux is.
        direct_handoff=False,
        default_mode="video",
        notes=(
            "v.redd.it is bare-fetchable without cookies (measured 206), but Reddit "
            "publishes DASH video and audio separately — a single URL is a silent "
            "clip, so the worker must mux. The fragile step is the metadata fetch, "
            "not the CDN: reddit.com rate-limits and 403s anonymous scripted clients, "
            "so expect intermittent resolve failures rather than download failures."
        ),
    ),
    "pinterest": PlatformSpec(
        name="Pinterest",
        patterns=_rx(
            SUB + r"pinterest\.[a-z]{2,3}(?:\.[a-z]{2})?/pin/[\w-]+",
            r"pin\.it/[\w-]+",
        ),
        direct_handoff=True,
        default_mode="video",
        notes=(
            "v1.pinimg.com serves unsigned progressive MP4 for video pins, which is "
            "about as friendly as a CDN gets. Some pins are HLS-only; the protocol "
            "check demotes those to the worker path. Idea Pins (multi-page) resolve "
            "to the first segment only, which is the honest behaviour given "
            "noplaylist."
        ),
    ),
    "youtube": PlatformSpec(
        name="YouTube",
        patterns=_rx(
            SUB + r"youtube\.com/watch\?(?:[^#]*&)?v=[\w-]{11}" + END,
            SUB + r"youtube(?:-nocookie)?\.com/(?:shorts|live|embed|v)/[\w-]{11}" + END,
            r"youtu\.be/[\w-]{11}" + END,
        ),
        direct_handoff=False,
        default_mode="audio",
        notes=(
            "Never direct. googlevideo.com URLs are bound to the IP that resolved "
            "them, so handing one to a browser on a different IP yields a 403 - and "
            "worse, an intermittent one that looks like a bug. On top of that, "
            "everything above 720p is adaptive (video-only + audio-only), so it needs "
            "muxing regardless. This is the one platform where bytes definitely flow "
            "through us, which is exactly why default_mode is audio: an MP3 is ~4MB "
            "where 1080p is ~120MB, and on residential proxies at ~$3-10/GB that "
            "difference is the entire cost model."
        ),
    ),
    "loom": PlatformSpec(
        name="Loom",
        patterns=_rx(
            SUB + r"loom\.com/(?:share|embed|v)/[0-9a-f]{16,}",
            SUB + r"loom\.com/(?:share|embed|v)/[\w-]{16,}",
        ),
        # MEASURED 2026-08-12. The original note here claimed Loom's URLs were
        # session-signed and would 403 for a browser. That is WRONG — a bare
        # curl with no headers and no cookies returned 206. The real reason Loom
        # cannot be a direct handoff is different, and stronger:
        #
        #   Loom serves ZERO progressive formats. Every video is split into
        #   separate video and audio streams (HLS `hls-raw-1500`/`hls-raw-3200`
        #   + `hls-raw-audio-audio`, or DASH vp9 + opus). Two public URLs, and
        #   neither is playable alone.
        #
        # So handing the browser one URL gives the user a silent video or a
        # bodiless audio file. Muxing is mandatory, which means ffmpeg, which
        # means the worker. (This is exactly the case cobalt solves with in-browser
        # WASM muxing — worth revisiting only if the worker becomes a bottleneck.)
        direct_handoff=False,
        default_mode="video",
        notes=(
            "Always split video/audio (HLS or DASH), never progressive, so a mux is "
            "mandatory and it must go through the worker. The CDN URLs themselves are "
            "publicly fetchable — the blocker is the mux, not access control. Only "
            "public share links resolve; private and workspace-restricted videos "
            "return an extractor error, which is correct behaviour."
        ),
    ),
    "twitch": PlatformSpec(
        name="Twitch",
        patterns=_rx(
            SUB + r"twitch\.tv/videos/\d+",
            SUB + r"twitch\.tv/[\w]+/(?:v|video)/\d+",
            SUB + r"twitch\.tv/[\w]+/clip/[\w-]+",
            r"clips\.twitch\.tv/[\w-]+",
        ),
        direct_handoff=False,
        default_mode="video",
        notes=(
            "VODs are HLS only - there is no single file to hand over, the browser "
            "cannot assemble .ts segments into a download, so this is structurally "
            "worker-only. Clips do expose an MP4, but they are short enough that the "
            "worker cost is trivial and keeping one code path per platform is worth "
            "more than the saving. Live channels are rejected upstream as unbounded."
        ),
    ),
    "snapchat": PlatformSpec(
        name="Snapchat",
        patterns=_rx(
            SUB + r"snapchat\.com/spotlight/[\w-]+",
            SUB + r"snapchat\.com/p/[\w-]+/[\w-]+",
            SUB + r"snapchat\.com/add/[\w.\-]+/[\w-]+",
            SUB + r"snapchat\.com/u/[\w.\-]+/[\w-]+",
            r"t\.snapchat\.com/[\w-]+",
        ),
        direct_handoff=True,
        default_mode="video",
        notes=(
            "Public Spotlight media on cf-st.sc-cdn.net is served as plain progressive "
            "MP4 with no signature and no IP binding - it is effectively a static "
            "asset. Only public Spotlight/public-profile content is reachable at all; "
            "anything requiring an account fails at extraction, which is the correct "
            "outcome."
        ),
    ),
}

# Derived so there is exactly one source of truth. Flip the flag on the spec, not here.
#: Platforms whose CDN URL the browser can fetch itself, so the server moves no
#: bytes. This set is the entire cost model, and it must be MEASURED per platform
#: rather than assumed — a wrong `True` here does not fail loudly, it silently
#: hands users a URL that 403s.
#:
#: Verification status as of 2026-08-12:
#:   tiktok     MEASURED, cookie-bound -> False (see the spec above)
#:   instagram  UNVERIFIED (cobalt redirects it, so probably fetchable)
#:   facebook   UNVERIFIED (cobalt redirects it, so probably fetchable)
#:   pinterest  UNVERIFIED (cobalt redirects it, so probably fetchable)
#:   snapchat   UNVERIFIED (cobalt redirects it, so probably fetchable)
#:   threads    UNVERIFIED
#:   twitter    UNVERIFIED, and SUSPECT — cobalt tunnels X rather than redirecting
#:   reddit     UNVERIFIED, and SUSPECT — cobalt tunnels Reddit rather than redirecting
#:
#: Test procedure that settled TikTok, reusable for the rest: resolve the URL,
#: then curl the returned CDN address three ways — bare, with yt-dlp's headers,
#: and with the session cookies. If only the third returns 206, it is cookie-bound
#: and `direct_handoff` must be False.
DIRECT_HANDOFF: Final[set[str]] = {
    key for key, spec in SUPPORTED.items() if spec.direct_handoff
}


# --- Playlist / collection rejection -----------------------------------------
#
# WHY these are matched separately and *before* detect_platform: `noplaylist=True`
# stops yt-dlp from expanding a collection, but a user who pastes a channel URL
# then gets a confusing "unsupported platform" or a single arbitrary video. An
# explicit playlist_rejected is honest, and it stops one paste from becoming N
# jobs at the routing layer rather than relying solely on an extractor option.
#
# Deliberately NOT rejected: `watch?v=<id>&list=<id>`. That is the single most
# common shape a normal person pastes (they opened a video from a playlist), and
# `noplaylist=True` already resolves it to just that video. Rejecting it would
# fail real users to guard against a case yt-dlp has already handled.
_PLAYLIST_PATTERNS: Final[tuple[Pattern[str], ...]] = _rx(
    # YouTube collections
    SUB + r"youtube\.com/playlist\b",
    SUB + r"youtube\.com/(?:channel|c|user)/",
    SUB + r"youtube\.com/@[\w.\-]+(?:/(?:videos|shorts|streams|playlists|featured|releases))?/?(?:\?|$)",
    SUB + r"youtube\.com/(?:results|feed|hashtag|playlists)\b",
    # TikTok collections
    SUB + r"tiktok\.com/@[\w.\-]+/?(?:\?|$)",
    SUB + r"tiktok\.com/@[\w.\-]+/(?:playlist|collection)\b",
    SUB + r"tiktok\.com/(?:tag|explore|foryou|discover|music)\b",
    # Instagram / Threads collections
    SUB + r"instagram\.com/explore\b",
    SUB + r"instagram\.com/[\w.\-]+/(?:reels|tagged|saved)/?(?:\?|$)",
    SUB + r"threads\.(?:net|com)/@[\w.\-]+/?(?:\?|$)",
    # Reddit listings
    SUB + r"reddit\.com/r/[\w-]+/?(?:\?|$)",
    SUB + r"reddit\.com/r/[\w-]+/(?:hot|new|top|rising|best|about)\b",
    # Vimeo collections
    SUB + r"vimeo\.com/(?:album|showcase|groups|channels)/[\w-]+/?(?:\?|$)",
    # Twitch listings
    SUB + r"twitch\.tv/[\w]+/videos\b",
    SUB + r"twitch\.tv/directory\b",
    # Facebook listings
    SUB + r"facebook\.com/[\w.\-]+/videos/?(?:\?|$)",
    # Pinterest boards and saved feeds
    SUB + r"pinterest\.[a-z]{2,3}(?:\.[a-z]{2})?/[\w.\-]+/_(?:saved|created)\b",
    # Generic: any /playlist(s)/ path segment on a host we otherwise support
    r"[a-z0-9.-]+/playlists?/",
)


def normalize_url(url: str) -> str | None:
    """Reduce a pasted URL to the ``host + path [+ ?query]`` subject we match on.

    WHY normalise instead of matching the raw string: users paste with and without
    a scheme, with ``www.``, with tracking query junk, with trailing slashes, and
    occasionally with mixed case in the host. Folding all of that here means every
    pattern in this module can stay short and readable instead of each one
    re-implementing the same tolerance.

    Returns None for anything that is not a plausible http(s) URL - including
    ``javascript:``/``data:``/``file:`` schemes, which must never reach yt-dlp.
    """
    if not url:
        return None
    candidate = url.strip()
    if not candidate or len(candidate) > MAX_URL_LEN:
        return None

    # Protocol-relative and bare-host pastes are both extremely common.
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif "://" not in candidate:
        # Reject scheme-like prefixes we do not allow before assuming it is bare.
        if re.match(r"^[a-z][a-z0-9+.\-]*:", candidate, re.IGNORECASE):
            return None
        candidate = "https://" + candidate

    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None

    if parts.scheme.lower() not in ("http", "https"):
        return None

    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    if host.startswith("www."):
        host = host[4:]

    path = parts.path or ""
    while len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    subject = host + path
    if parts.query:
        subject += "?" + parts.query
    return subject


def detect_platform(url: str) -> str | None:
    """Return the SUPPORTED key for a media URL, or None if we do not handle it.

    Returns None (not an exception) so callers can decide between
    ``unsupported_platform`` and ``playlist_rejected`` themselves - check
    :func:`is_playlist_url` first, because a channel URL is None here too and the
    playlist message is far more useful to the person who pasted it.
    """
    subject = normalize_url(url)
    if subject is None:
        return None
    for key, spec in SUPPORTED.items():
        for pattern in spec.patterns:
            if pattern.match(subject):
                return key
    return None


def is_playlist_url(url: str) -> bool:
    """True when the URL denotes a collection rather than one piece of media.

    Callers should test this BEFORE :func:`detect_platform` and raise
    ``playlist_rejected``. One pasted channel URL turning into 200 queued jobs is
    the single easiest way for this service to bankrupt itself, so the guard lives
    at the edge and does not depend on any extractor behaviour.
    """
    subject = normalize_url(url)
    if subject is None:
        return False
    for pattern in _PLAYLIST_PATTERNS:
        if pattern.match(subject):
            return True
    # A `list=` with no `v=` is a playlist page in disguise (e.g. a shared mix).
    if "?" in subject:
        query = subject.split("?", 1)[1]
        params = {p.split("=", 1)[0].lower() for p in query.split("&") if p}
        if "list" in params and "v" not in params:
            return True
    return False
