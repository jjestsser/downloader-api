"""Resolver package: platform detection, yt-dlp extraction, proxies, health canary.

Nothing is re-exported here on purpose. ``canary`` imports ``ytdlp`` which imports
``proxies`` and ``platforms``, so eagerly importing the subpackage would drag
``yt_dlp`` into any process that only wanted ``detect_platform`` - including the
API route that rejects unsupported URLs before an extractor is ever needed.
Import the module you actually want.
"""
