"""The service's entire error vocabulary.

WHY a closed set of codes: the front-end switches on `error` to pick a message,
and the metrics endpoint counts rejections by code. A free-text error string
would make both of those unreliable, and — more importantly — a stringified
exception is exactly how a URL or a proxy credential ends up in a response body.
`detail` is therefore always a constant we wrote, never an exception's `str()`.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import Request
from fastapi.responses import JSONResponse

#: code -> HTTP status. This mapping is the contract; do not extend it casually.
ERROR_CODES: Final[dict[str, int]] = {
    "ticket_missing": 401,
    "ticket_bad_signature": 401,
    "ticket_expired": 401,
    "ticket_replayed": 401,
    "ticket_wrong_audience": 401,
    "turnstile_failed": 403,
    "quota_exceeded": 429,
    "killswitch_active": 503,
    "unsupported_platform": 400,
    "playlist_rejected": 400,
    "video_too_long": 422,
    "file_too_large": 413,
    "extractor_failed": 502,
    "platform_degraded": 503,
    "job_not_found": 404,
    "internal": 500,
    # Framework-level failures. These are raised by main.py's handlers rather
    # than by business logic, but they must live here: the front-end switches on
    # `error` and /metrics counts by code, so a response carrying a code outside
    # this table is one neither can classify. `invalid_request` in particular
    # shares its 422 with `video_too_long`, and only the code tells them apart.
    "invalid_request": 422,
    "not_found": 404,
    "method_not_allowed": 405,
    "http_error": 400,
}

#: Human-facing default text. Safe to show a user verbatim: no URLs, no internals.
DEFAULT_DETAIL: Final[dict[str, str]] = {
    "ticket_missing": "This request is missing its download ticket. Reload the page and try again.",
    "ticket_bad_signature": "This download ticket is not valid. Reload the page and try again.",
    "ticket_expired": "This download ticket has expired. Reload the page and try again.",
    "ticket_replayed": "This download ticket has already been used.",
    "ticket_wrong_audience": "This download ticket was not issued for this service.",
    "turnstile_failed": "The human check did not pass. Please try again.",
    "quota_exceeded": "You have reached today's download limit. Try again tomorrow.",
    "killswitch_active": "Downloads are paused right now. Please try again later.",
    "unsupported_platform": "That link is from a site this tool does not support.",
    "playlist_rejected": "That link points to a playlist or channel. Paste a link to a single video.",
    "video_too_long": "That video is longer than this tool allows.",
    "file_too_large": "That file is larger than this tool allows.",
    "extractor_failed": "Could not read that link. The post may be private, deleted or region-locked.",
    "platform_degraded": "That platform is temporarily unavailable. Please try again later.",
    "job_not_found": "That download job does not exist or has expired.",
    "internal": "Something went wrong on our side.",
    "invalid_request": "That request was not in a form this service understands.",
    "not_found": "There is nothing at this address.",
    "method_not_allowed": "That HTTP method is not allowed here.",
    "http_error": "That request could not be handled.",
}

#: Codes we never want to see in a 5xx alert because they are the user's doing.
CLIENT_CODES: Final[frozenset[str]] = frozenset(
    code for code, status in ERROR_CODES.items() if status < 500
)


class ApiError(Exception):
    """A deliberate, user-visible failure.

    Raise this anywhere in the request path; `api_error_handler` turns it into
    the JSON body the front-end expects. Anything else that escapes is a bug and
    is reported as `internal` with no detail at all.
    """

    __slots__ = ("code", "status", "detail", "headers")

    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        status: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if code not in ERROR_CODES and status is None:
            # An unknown code is a programming error, but a 500 in production is
            # better than an AttributeError inside an exception handler.
            code, status = "internal", 500
        self.code: str = code
        self.status: int = status if status is not None else ERROR_CODES[code]
        self.detail: str = detail or DEFAULT_DETAIL.get(code, "Request failed.")
        self.headers: dict[str, str] = headers or {}
        super().__init__(f"{self.code}: {self.detail}")

    @property
    def is_client_error(self) -> bool:
        return self.status < 500

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "detail": self.detail}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ApiError(code={self.code!r}, status={self.status})"


def error_response(
    code: str,
    detail: str | None = None,
    *,
    status: int | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build the canonical error body without raising. Useful in dependencies."""
    err = ApiError(code, detail, status=status, headers=headers)
    return JSONResponse(status_code=err.status, content=err.to_dict(), headers=err.headers or None)


async def api_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """FastAPI exception handler for `ApiError`.

    Signature is `(request, exc: Exception)` rather than `(request, exc: ApiError)`
    because Starlette's handler registry is typed that way; the narrowing happens
    here.
    """
    if not isinstance(exc, ApiError):  # pragma: no cover - defensive
        exc = ApiError("internal")
    return JSONResponse(
        status_code=exc.status,
        content=exc.to_dict(),
        headers=exc.headers or None,
    )
