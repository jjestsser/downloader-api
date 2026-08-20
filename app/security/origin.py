"""Proof that a request arrived through the edge, rather than at the origin.

Railway publishes every service on a `*.up.railway.app` hostname and offers no
origin IP allowlist, so a custom domain behind Cloudflare protects the domain
and not the service: anyone who knows the Railway hostname reaches the app
directly, past every WAF rule, rate limit and header rewrite.

A Cloudflare Transform Rule sets `X-Edge-Token` on all proxied requests. A
request without it did not come through Cloudflare.

Two things are built on that:

* `require_edge`, which refuses such requests outright. Applied to the routers
  that cost money.
* `came_through_edge`, which decides whether `CF-Connecting-IP` may be believed.
  That header is the one Cloudflare sets to the true client address after
  stripping any copy the client sent — and it is *only* those things when
  Cloudflare is actually in front. On a bare Railway hostname nothing strips it,
  so it is simply a string the caller chose.

The second one is what closes a measured hole. Reading `CF-Connecting-IP`
unconditionally, as this service did, meant a caller could present the same
fabricated address to the ticket minter and to this service, have the two agree,
and land in a per-IP quota bucket of their own choosing. Verified against the
deployed service on 2026-08-21: a ticket minted for 198.51.100.7 and presented
with `CF-Connecting-IP: 198.51.100.7` was accepted, while the same trick through
`X-Forwarded-For` was refused, because Railway's proxy overwrites that one.

Unset means unconfigured, and unconfigured means "no edge in front" rather than
"edge checks off". Both functions then behave as if the header were absent,
which is what makes local development and the tests work without a secret while
still refusing to trust a header nobody vouched for.
"""

from __future__ import annotations

import hmac

from fastapi import Request

from app.errors import ApiError
from app.settings import settings

__all__ = ["came_through_edge", "require_edge", "EDGE_TOKEN_HEADER"]

#: Set by a Cloudflare Transform Rule on every proxied request.
EDGE_TOKEN_HEADER = "X-Edge-Token"


def came_through_edge(request: Request) -> bool:
    """True only when this request carries the shared secret Cloudflare adds."""
    expected = settings.origin_shared_token
    if not expected:
        # No secret configured: there is no edge, so nothing came through one.
        # Deliberately not `True` — that would restore the very trust this
        # module exists to withdraw.
        return False
    presented = request.headers.get(EDGE_TOKEN_HEADER, "")
    return bool(presented) and hmac.compare_digest(presented, expected)


async def require_edge(request: Request) -> None:
    """Refuses anything that reached the origin directly.

    Answers 404 rather than 401 or 403: a direct-to-origin prober learns that
    the hostname serves nothing interesting, instead of learning that they found
    the right service and only need the right header.

    A no-op until `ORIGIN_SHARED_TOKEN` is set, so the service keeps working
    before the Cloudflare rule exists and in local development.
    """
    if not settings.origin_shared_token:
        return
    if not came_through_edge(request):
        raise ApiError("job_not_found", "Not found.", 404)
