"""JSON logging to stdout, with URL redaction wired in at the handler.

WHY the redaction filter exists even though the code is written never to log a
URL: "never log URLs" is a rule humans forget under pressure, and yt-dlp,
botocore and httpx all cheerfully put full URLs in their own log records and
tracebacks. A rule enforced only by discipline is not enforced. So every record
that reaches stdout passes through `URLRedactionFilter`, which rewrites anything
URL-shaped — in the message, in the args, in the structured fields and in
formatted tracebacks — into `[url#<16 hex>]`.

The hash is deterministic, so support can still answer "did these two failures
come from the same link?" without the service ever holding a record of who
downloaded what. That record has no product value and is the single worst thing
to be holding if a legal request arrives.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from typing import Any, Final

from app.settings import settings

SERVICE_NAME: Final[str] = "downloader"

#: Key under which structured fields are smuggled through `extra`. Nesting them
#: keeps us from colliding with reserved LogRecord attributes like `name`.
_CTX_KEY: Final[str] = "ctx"

#: Anything with a scheme and an authority, plus bare `www.` hosts. Deliberately
#: greedy: a false positive costs a hashed token in a log line, a false negative
#: costs a permanent record of a user's media URL.
_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://|www\.)[^\s'\"<>\\)\]}]{2,}"
)

#: kwargs that stdlib logging understands; everything else is a structured field.
_LOG_KWARGS: Final[frozenset[str]] = frozenset({"exc_info", "stack_info", "stacklevel", "extra"})

#: Attributes present on every LogRecord; used to spot caller-supplied extras.
_RECORD_ATTRS: Final[frozenset[str]] = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__.keys()
) | {"message", "asctime", "taskName"}

_MAX_REDACT_DEPTH: Final[int] = 6


def hash_url(url: str) -> str:
    """Stable 16-hex-char digest of a URL. The only form a URL may be logged in."""
    return hashlib.sha256(url.strip().encode("utf-8", "replace")).hexdigest()[:16]


def _redact_str(value: str) -> str:
    return _URL_RE.sub(lambda m: f"[url#{hash_url(m.group(0))}]", value)


def _redact(value: Any, depth: int = 0) -> Any:
    """Recursively rewrite URL-shaped substrings in anything loggable."""
    if depth > _MAX_REDACT_DEPTH:
        return value
    if isinstance(value, str):
        return _redact_str(value)
    if isinstance(value, Mapping):
        return {k: _redact(v, depth + 1) for k, v in value.items()}
    if isinstance(value, tuple):
        return tuple(_redact(v, depth + 1) for v in value)
    if isinstance(value, list):
        return [_redact(v, depth + 1) for v in value]
    if isinstance(value, set):
        return {_redact(v, depth + 1) for v in value}
    return value


class URLRedactionFilter(logging.Filter):
    """Defence in depth for the no-URL-logging rule. Attached to every handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _redact_str(record.msg)
        if record.args:
            record.args = _redact(record.args)  # type: ignore[assignment]
        ctx = record.__dict__.get(_CTX_KEY)
        if isinstance(ctx, Mapping):
            record.__dict__[_CTX_KEY] = _redact(ctx)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line, which is what Railway's log drain wants."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
            "service": SERVICE_NAME,
            "env": settings.environment,
        }

        ctx = record.__dict__.get(_CTX_KEY)
        if isinstance(ctx, Mapping):
            for key, value in ctx.items():
                payload.setdefault(str(key), value)

        # Extras passed the stdlib way (`extra={"foo": 1}`) still get through.
        for key, value in record.__dict__.items():
            if key not in _RECORD_ATTRS and key != _CTX_KEY:
                payload.setdefault(key, value)

        if record.exc_info:
            payload["exc"] = _redact_str(self.formatException(record.exc_info))
        if record.stack_info:
            payload["stack"] = _redact_str(self.formatStack(record.stack_info))

        return json.dumps(payload, default=str, ensure_ascii=False)


class StructLogger(logging.LoggerAdapter):
    """structlog-style call sites on top of the stdlib.

    `log.info("resolve_ok", platform="tiktok", ms=412)` instead of f-strings, so
    the fields stay queryable and nobody is tempted to interpolate a URL into a
    message.
    """

    def process(self, msg: Any, kwargs: MutableMapping[str, Any]) -> tuple[Any, MutableMapping[str, Any]]:
        fields = {key: kwargs.pop(key) for key in list(kwargs) if key not in _LOG_KWARGS}
        explicit_extra = dict(kwargs.get("extra") or {})
        bound = dict(self.extra or {})
        kwargs["extra"] = {_CTX_KEY: {**bound, **fields, **explicit_extra}}
        return msg, kwargs

    def bind(self, **fields: Any) -> StructLogger:
        """Return a child logger carrying `fields` on every record."""
        return StructLogger(self.logger, {**(self.extra or {}), **fields})


#: The service logger. Import this, do not call `logging.getLogger` directly.
log: Final[StructLogger] = StructLogger(logging.getLogger(SERVICE_NAME), {})

_configured = False


def setup_logging(level: str | None = None) -> None:
    """Install the JSON handler on the root logger. Idempotent and re-entrant.

    Called from the API lifespan and from the arq worker startup, because both
    processes need identical log shape for a single drain to be useful.
    """
    global _configured

    resolved = (level or settings.log_level or "INFO").upper()
    numeric = getattr(logging, resolved, logging.INFO)

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(URLRedactionFilter())
    root.addHandler(handler)
    root.setLevel(numeric)

    # WHY seize these loggers: uvicorn and arq install their own coloured
    # handlers at startup. Left alone they would emit unredacted, non-JSON lines
    # straight past our filter.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "gunicorn.error", "arq", "arq.worker"):
        lib = logging.getLogger(name)
        lib.handlers.clear()
        lib.propagate = True

    # Access logs put the request target (query string included) on every line.
    # Our own middleware logs the matched route instead, which cannot carry a
    # user-supplied URL.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    for noisy in ("botocore", "boto3", "s3transfer", "urllib3", "httpx", "httpcore", "asyncio", "yt_dlp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.captureWarnings(True)
    _configured = True


def is_configured() -> bool:
    return _configured
