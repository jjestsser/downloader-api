"""Tests for URL detection and playlist rejection.

These are the cheapest tests in the service and they guard the two most expensive
mistakes: sending an unsupported URL into an extractor, and letting one pasted
channel link fan out into hundreds of jobs. Every URL shape below is one a real
user pastes - share sheets, mobile hosts, short links, and the tracking query
junk that every platform's copy button attaches.
"""

from __future__ import annotations

import pytest

from app.resolver.platforms import (
    DIRECT_HANDOFF,
    SUPPORTED,
    detect_platform,
    is_playlist_url,
    normalize_url,
)

# --- (url, expected platform) -------------------------------------------------
DETECT_CASES: list[tuple[str, str]] = [
    # TikTok: desktop, no-www, mobile host, both short-link hosts, /t/ share link,
    # photo posts, and the tracking params the share sheet appends.
    ("https://www.tiktok.com/@charlidamelio/video/7231234567890123456", "tiktok"),
    ("https://tiktok.com/@user.name/video/7231234567890123456", "tiktok"),
    ("https://m.tiktok.com/@user/video/7231234567890123456", "tiktok"),
    ("https://vm.tiktok.com/ZMabcdefg/", "tiktok"),
    ("https://vt.tiktok.com/ZSabcdefg/", "tiktok"),
    ("https://www.tiktok.com/t/ZTabcdefg/", "tiktok"),
    ("https://www.tiktok.com/@user/photo/7231234567890123456", "tiktok"),
    (
        "https://www.tiktok.com/@user/video/7231234567890123456?is_from_webapp=1&sender_device=pc",
        "tiktok",
    ),
    # Instagram: posts, reels (both spellings), IGTV, stories, profile-prefixed
    # reel URLs, the instagr.am alias, and the ?igshid= share param.
    ("https://www.instagram.com/p/CxAbCdEfGhI/", "instagram"),
    ("https://instagram.com/reel/CxAbCdEfGhI/", "instagram"),
    ("https://www.instagram.com/reels/CxAbCdEfGhI/", "instagram"),
    ("https://www.instagram.com/tv/CxAbCdEfGhI/", "instagram"),
    ("https://www.instagram.com/kavitha.codes/reel/CxAbCdEfGhI/", "instagram"),
    ("https://www.instagram.com/stories/natgeo/3245678901234567890/", "instagram"),
    ("https://instagr.am/p/CxAbCdEfGhI/", "instagram"),
    ("https://www.instagram.com/p/CxAbCdEfGhI/?igshid=MzRlODBiNWFlZA==", "instagram"),
    # Facebook: classic /videos/, watch?v=, reels, m. host, fb.watch, /share/v/.
    ("https://www.facebook.com/natgeo/videos/1234567890123456/", "facebook"),
    ("https://facebook.com/watch/?v=1234567890123456", "facebook"),
    ("https://www.facebook.com/reel/1234567890123456", "facebook"),
    ("https://m.facebook.com/natgeo/video/1234567890123456", "facebook"),
    ("https://fb.watch/abcDEF123x/", "facebook"),
    ("https://www.facebook.com/share/v/abcDEF123/", "facebook"),
    ("https://www.facebook.com/video.php?v=1234567890123456", "facebook"),
    # X / Twitter: both domains, mobile host, /i/status, plural /statuses/,
    # and the ?s=20&t= share tail.
    ("https://twitter.com/nasa/status/1234567890123456789", "twitter"),
    ("https://x.com/nasa/status/1234567890123456789", "twitter"),
    ("https://mobile.twitter.com/nasa/status/1234567890123456789", "twitter"),
    ("https://twitter.com/i/status/1234567890123456789", "twitter"),
    ("https://twitter.com/nasa/statuses/1234567890123456789", "twitter"),
    ("https://x.com/nasa/status/1234567890123456789?s=20&t=AbCdEf", "twitter"),
    # Reddit: full comment permalink, old. host, new /s/ share link, both short
    # hosts, and a user-profile post.
    ("https://www.reddit.com/r/videos/comments/abc123/some_title_slug/", "reddit"),
    ("https://old.reddit.com/r/videos/comments/abc123/some_title_slug/", "reddit"),
    ("https://www.reddit.com/r/videos/s/AbCdEfGhIj", "reddit"),
    ("https://redd.it/abc123", "reddit"),
    ("https://v.redd.it/abcdefghij123", "reddit"),
    ("https://www.reddit.com/user/someone/comments/abc123/title/", "reddit"),
    # Pinterest: .com, regional TLDs, pin.it short link.
    ("https://www.pinterest.com/pin/1234567890123456789/", "pinterest"),
    ("https://pinterest.co.uk/pin/1234567890123456789/", "pinterest"),
    ("https://in.pinterest.com/pin/1234567890123456789/", "pinterest"),
    ("https://pin.it/abcDEF12", "pinterest"),
    # YouTube: watch, youtu.be, shorts, live, embed, music/mobile hosts, nocookie,
    # timestamped links, and a video opened from inside a playlist (noplaylist
    # handles that one - it must NOT be rejected).
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "youtube"),
    ("https://youtube.com/watch?v=dQw4w9WgXcQ", "youtube"),
    ("https://youtu.be/dQw4w9WgXcQ", "youtube"),
    ("https://youtu.be/dQw4w9WgXcQ?t=42", "youtube"),
    ("https://www.youtube.com/shorts/dQw4w9WgXcQ", "youtube"),
    ("https://www.youtube.com/live/dQw4w9WgXcQ", "youtube"),
    ("https://www.youtube.com/embed/dQw4w9WgXcQ", "youtube"),
    ("https://m.youtube.com/watch?v=dQw4w9WgXcQ", "youtube"),
    ("https://music.youtube.com/watch?v=dQw4w9WgXcQ", "youtube"),
    ("https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ", "youtube"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLabcdef&index=3", "youtube"),
    ("https://www.youtube.com/watch?app=desktop&v=dQw4w9WgXcQ", "youtube"),
    # Vimeo: bare id, unlisted hash, channel, group, player embed.
    # Loom: share and embed forms.
    ("https://www.loom.com/share/0123456789abcdef0123456789abcdef", "loom"),
    ("https://loom.com/embed/0123456789abcdef0123456789abcdef", "loom"),
    # Twitch: VOD, clip on channel, clips. host.
    ("https://www.twitch.tv/videos/1234567890", "twitch"),
    ("https://twitch.tv/somestreamer/clip/HappyFunnyClipName", "twitch"),
    ("https://clips.twitch.tv/HappyFunnyClipName", "twitch"),
    # (Threads removed: yt-dlp ships no Threads extractor.)
    # Snapchat: spotlight and public-profile media.
    ("https://www.snapchat.com/spotlight/W7_EDlXWTBiXAEEniNoMPwAAYc", "snapchat"),
    ("https://t.snapchat.com/AbCdEf12", "snapchat"),
]

# Bare-host, scheme-less and protocol-relative pastes must still resolve. People
# copy out of a browser omnibox constantly.
LENIENT_CASES: list[tuple[str, str]] = [
    ("www.youtube.com/watch?v=dQw4w9WgXcQ", "youtube"),
    ("youtu.be/dQw4w9WgXcQ", "youtube"),
    ("//www.tiktok.com/@user/video/7231234567890123456", "tiktok"),
    ("HTTPS://WWW.TikTok.com/@User/Video/7231234567890123456", "tiktok"),
    ("  https://x.com/nasa/status/1234567890123456789  ", "twitter"),
]

# Must NOT match any platform: profiles, homepages, look-alike domains, other
# hosts, and non-http schemes.
UNSUPPORTED_URLS: list[str] = [
    "https://www.dailymotion.com/video/x8abcde",
    "https://example.com/video.mp4",
    "https://nottiktok.com/@user/video/7231234567890123456",
    "https://tiktok.com.evil.example/@user/video/7231234567890123456",
    "https://evil.example/https://www.tiktok.com/@user/video/123",
    "https://www.youtube.com",
    "https://vimeo.com/",
    "https://www.instagram.com/",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "ftp://files.example.com/movie.mp4",
    "",
    "   ",
    "not a url at all",
]

# Collections. Every one of these must be rejected BEFORE it reaches yt-dlp.
PLAYLIST_URLS: list[str] = [
    "https://www.youtube.com/playlist?list=PLabcdefghijklmnop",
    "https://www.youtube.com/watch?list=PLabcdefghijklmnop",
    "https://www.youtube.com/channel/UCabcdefghijklmnopqrstuv",
    "https://www.youtube.com/c/SomeChannel",
    "https://www.youtube.com/user/SomeChannel",
    "https://www.youtube.com/@somechannel",
    "https://www.youtube.com/@somechannel/videos",
    "https://www.youtube.com/@somechannel/shorts",
    "https://www.youtube.com/@somechannel/streams",
    "https://www.youtube.com/results?search_query=cats",
    "https://www.youtube.com/feed/trending",
    "https://www.youtube.com/hashtag/shorts",
    "https://www.tiktok.com/@charlidamelio",
    "https://www.tiktok.com/@charlidamelio/playlist/Dances-7123456789",
    "https://www.tiktok.com/tag/fyp",
    "https://www.instagram.com/explore/tags/travel/",
    "https://www.instagram.com/natgeo/reels/",
    "https://www.threads.net/@zuck",
    "https://www.reddit.com/r/videos/",
    "https://www.reddit.com/r/videos/top/",
    "https://vimeo.com/channels/staffpicks",
    "https://vimeo.com/showcase/1234567",
    "https://vimeo.com/album/1234567",
    "https://www.twitch.tv/somestreamer/videos",
    "https://www.twitch.tv/directory/game/Chess",
    "https://www.facebook.com/natgeo/videos/",
]

# Single-item URLs that superficially look collection-ish and must be ACCEPTED.
NOT_PLAYLIST_URLS: list[str] = [
    # The most common real paste in existence: a video opened from a playlist.
    # noplaylist=True already resolves this to one video; rejecting it would fail
    # a huge number of legitimate users.
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLabcdef&index=3",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://youtu.be/dQw4w9WgXcQ",
    "https://vimeo.com/channels/staffpicks/123456789",
    "https://vimeo.com/groups/motion/videos/123456789",
    "https://www.twitch.tv/videos/1234567890",
    "https://www.tiktok.com/@charlidamelio/video/7231234567890123456",
    "https://www.reddit.com/r/videos/comments/abc123/title/",
    "https://www.facebook.com/natgeo/videos/1234567890123456/",
]


@pytest.mark.parametrize(("url", "expected"), DETECT_CASES, ids=[u for u, _ in DETECT_CASES])
def test_detect_platform_matches_real_url_shapes(url: str, expected: str) -> None:
    assert detect_platform(url) == expected


@pytest.mark.parametrize(("url", "expected"), LENIENT_CASES, ids=[u for u, _ in LENIENT_CASES])
def test_detect_platform_tolerates_sloppy_pastes(url: str, expected: str) -> None:
    assert detect_platform(url) == expected


@pytest.mark.parametrize("url", UNSUPPORTED_URLS)
def test_detect_platform_returns_none_for_unsupported(url: str) -> None:
    assert detect_platform(url) is None


@pytest.mark.parametrize("url", PLAYLIST_URLS)
def test_playlist_urls_are_rejected(url: str) -> None:
    assert is_playlist_url(url) is True


@pytest.mark.parametrize("url", NOT_PLAYLIST_URLS)
def test_single_media_urls_are_not_playlists(url: str) -> None:
    assert is_playlist_url(url) is False


@pytest.mark.parametrize("url", PLAYLIST_URLS)
def test_playlist_urls_never_resolve_to_a_single_video(url: str) -> None:
    """A collection URL must not sneak through as a normal media URL.

    The route checks is_playlist_url first, but if detection ALSO matched one of
    these, an ordering mistake anywhere upstream would silently turn a channel
    into a job. Belt and braces.
    """
    assert detect_platform(url) is None


def test_direct_handoff_is_derived_from_specs() -> None:
    assert DIRECT_HANDOFF == {k for k, v in SUPPORTED.items() if v.direct_handoff}
    assert DIRECT_HANDOFF <= set(SUPPORTED)


def test_youtube_is_never_direct_handoff() -> None:
    """googlevideo URLs are IP-bound; handing one to a browser 403s.

    If this ever flips, users get intermittent, unreproducible failures - the
    worst possible bug class. It is worth a dedicated test.
    """
    assert "youtube" not in DIRECT_HANDOFF
    assert SUPPORTED["youtube"].default_mode == "audio"


def test_all_platforms_are_documented() -> None:
    """Every spec must explain WHY its handoff flag is set the way it is."""
    for key, spec in SUPPORTED.items():
        assert spec.name, f"{key} has no display name"
        assert spec.patterns, f"{key} has no URL patterns"
        assert len(spec.notes) > 80, f"{key} needs a real rationale in notes"
        assert spec.default_mode in ("video", "audio")


def test_expected_platform_coverage() -> None:
    assert set(SUPPORTED) == {
        "tiktok",
        "instagram",
        "facebook",
        "twitter",
        "reddit",
        "pinterest",
        "youtube",
        "loom",
        "twitch",
        "snapchat",
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://www.youtube.com/watch?v=abc", "youtube.com/watch?v=abc"),
        ("https://WWW.TikTok.com/@User/", "tiktok.com/@User"),
        ("http://old.reddit.com/r/x/comments/y/", "old.reddit.com/r/x/comments/y"),
        ("https://example.com", "example.com"),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_normalize_url_rejects_dangerous_and_oversized_input() -> None:
    assert normalize_url("javascript:alert(1)") is None
    assert normalize_url("data:text/plain,hi") is None
    assert normalize_url("https://example.com/" + "a" * 4000) is None
    assert normalize_url("https://localhost/video") is None  # no dot: not a real host


def test_detection_is_cheap_enough_to_run_on_every_request() -> None:
    """Guards against a pathological pattern being added later.

    Detection runs before any quota is consumed, so it is reachable by unpriced
    traffic. It must stay linear-ish on junk input.
    """
    import time

    junk = "https://example.com/" + "a-" * 500
    start = time.perf_counter()
    for _ in range(200):
        detect_platform(junk)
    assert (time.perf_counter() - start) < 1.0
