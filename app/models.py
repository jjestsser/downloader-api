"""Wire models shared by the API, the queue and the front-end.

These field names are the contract. The TypeScript client is generated against
them by hand, so renaming a field here is a breaking change everywhere.

WHY `extra="forbid"` on the request models: the only untrusted JSON we accept is
`JobCreateRequest`, and silently dropping unknown keys is how a client ends up
believing it passed an option that the server ignored.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Delivery = Literal["direct", "job"]
Mode = Literal["video", "audio"]
JobState = Literal["queued", "running", "done", "failed"]

#: A URL long enough to be a real share link but short enough that it cannot be
#: used to push megabytes of junk through the extractor.
MAX_URL_LEN = 2048


class MediaFormat(BaseModel):
    """One selectable rendition of a piece of media.

    `direct_url` is populated only for platforms in `DIRECT_HANDOFF` whose CDN
    URLs are fetchable straight from the browser. When it is set the client
    downloads from the CDN and this service moves zero bytes; when it is None
    the client must create a job and the worker pays the egress.
    """

    model_config = ConfigDict(extra="ignore")

    format_id: str
    ext: str
    label: str
    height: int | None = None
    filesize: int | None = None
    has_audio: bool
    has_video: bool
    direct_url: str | None = None


class ResolveResponse(BaseModel):
    """Metadata + formats for a single item. Never a playlist."""

    model_config = ConfigDict(extra="ignore")

    platform: str
    title: str
    duration_s: int | None = None
    thumbnail: str | None = None
    uploader: str | None = None
    formats: list[MediaFormat] = Field(default_factory=list)
    delivery: Delivery


class JobCreateRequest(BaseModel):
    """Client request to run a server-side download."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=MAX_URL_LEN)
    format_id: str = Field(min_length=1, max_length=200)
    mode: Mode = "video"

    @field_validator("url")
    @classmethod
    def _http_only(cls, value: str) -> str:
        """Reject file://, data:// and friends before yt-dlp ever sees them."""
        cleaned = value.strip()
        if not cleaned.lower().startswith(("http://", "https://")):
            raise ValueError("url must be an http(s) URL")
        if any(ch in cleaned for ch in ("\n", "\r", "\t", " ")):
            raise ValueError("url must not contain whitespace")
        return cleaned

    @field_validator("format_id")
    @classmethod
    def _safe_format_id(cls, value: str) -> str:
        """Format ids are echoed into yt-dlp's selector string.

        The alphabet covers what real extractors emit (`137`, `hls-1080`,
        `dash-audio_und=128000`, `http-1080@60`) plus the `+`/`/` a merge
        selector needs, and nothing else. It excludes the characters that turn a
        format id into a filter expression — `[`, `]`, `,`, `*`, `?`, spaces —
        so a hostile client cannot smuggle a selector through this field.
        """
        cleaned = value.strip()
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-./=~:@")
        if not cleaned or not set(cleaned) <= allowed:
            raise ValueError("format_id contains unsupported characters")
        return cleaned


class JobStatus(BaseModel):
    """Poll response for a queued download.

    `download_url` is a presigned R2 URL and is only present in state `done`;
    `expires_at` is the unix second at which that presign dies.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    state: JobState
    progress: int = Field(default=0, ge=0, le=100)
    error_code: str | None = None
    download_url: str | None = None
    expires_at: int | None = None

    #: The exception behind an `internal` failure, outside production only.
    #:
    #: `internal` is the code for "something we did not anticipate", which makes
    #: it the one failure with no diagnostic value at all — a refused connection,
    #: an unwritable directory and a genuine bug are one string. Recovering the
    #: difference meant reading the host's logs, and a staging service whose logs
    #: you must open to learn anything is a service you debug by guessing.
    #:
    #: Suppressed in production because it is a raw exception message: it can
    #: carry paths, hostnames and occasionally fragments of a URL that a public
    #: endpoint has no business handing out. `queue.job_status` decides.
    error_detail: str | None = None


class TicketClaims(BaseModel):
    """Verified payload of an `X-Download-Ticket` header.

    `ip_hash` is a salted, truncated digest — never a raw address — because it is
    also the quota key and quota keys outlive the request.
    """

    model_config = ConfigDict(extra="ignore")

    jti: str
    aud: str
    exp: int
    ip_hash: str
