"""Background download jobs.

The worker path exists only for media this service cannot hand straight to the
browser: YouTube (IP-bound URLs), and anything whose best video and best audio
are separate streams that must be muxed. Everything in `DIRECT_HANDOFF` skips
this package entirely and costs nothing but a metadata call.
"""
