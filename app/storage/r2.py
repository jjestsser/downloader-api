"""Cloudflare R2 object storage.

WHY R2 AND NOT S3: the worker path only exists because some platforms (YouTube) cannot
be handed off directly to the browser — we have to move the bytes ourselves. Moving bytes
twice (ingest to the worker, egress to the user) is the entire cost of that path. S3 charges
~$0.09/GB egress, which turns a 200 MB video into ~1.8 cents of pure egress and makes the
worker path cost more than the product earns. R2 egress is $0.00/GB. Storage is $0.015/GB-month
and we hold objects for RESULT_TTL_S (6h) before a lifecycle rule reaps them, so the storage
line is rounding error. That single pricing difference is why the whole design is viable.

WHY PRESIGNED URLS AND NOT A PUBLIC BUCKET: a public bucket means any object key is guessable
forever and we would be hosting an open media CDN for whoever finds it. A presigned GET is
scoped to one key and expires with the job result, so a leaked link dies on its own.
"""

from __future__ import annotations

import asyncio
import mimetypes
from pathlib import Path
from typing import Any, Final

import aioboto3
import boto3
from botocore.client import Config as BotoConfig

from app.errors import ApiError
from app.logging_conf import log
from app.settings import settings

# R2 ignores the region but SigV4 requires one; "auto" is what Cloudflare documents.
_R2_REGION: Final[str] = "auto"

# Presigned URLs are handed to a browser that may retry on a flaky mobile connection.
# Anything below a minute produces spurious "signature expired" failures on real networks.
_MIN_PRESIGN_TTL_S: Final[int] = 60

_session: Final[aioboto3.Session] = aioboto3.Session()

# boto3's signer is pure local crypto (no network I/O), so a module-level sync client is safe
# to call from async code — generate_presigned_url never blocks on a socket.
_signer: boto3.client | None = None  # type: ignore[valid-type]


def _endpoint_url() -> str:
    """The S3-compatible endpoint for this account's R2 namespace.

    Delegates to settings so a local MinIO override is picked up here too —
    duplicating the format string was how the two drifted apart.
    """
    return settings.r2_endpoint_url


def _client_kwargs() -> dict[str, Any]:
    return {
        "endpoint_url": _endpoint_url(),
        "region_name": _R2_REGION,
        "aws_access_key_id": settings.r2_access_key_id,
        "aws_secret_access_key": settings.r2_secret_access_key,
        # R2 only speaks SigV4, and only path-style addressing on the account endpoint.
        "config": BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=10,
            read_timeout=120,
        ),
    }


def _get_signer() -> Any:
    global _signer
    if _signer is None:
        _signer = boto3.client("s3", **_client_kwargs())
    return _signer


def _content_type_for(key: str) -> str:
    guessed, _ = mimetypes.guess_type(key)
    return guessed or "application/octet-stream"


def _describe(exc: Exception) -> str:
    """A log-safe summary of an S3 failure that says which one it was.

    Logging only `type(exc).__name__` is what made this undiagnosable: botocore
    raises `ClientError` for a missing bucket, wrong credentials, a signature
    mismatch and a permissions denial alike, so the type alone rules nothing out.
    The S3 error code and HTTP status do distinguish them — `NoSuchBucket` versus
    `InvalidAccessKeyId` versus `SignatureDoesNotMatch` — and neither contains a
    secret.

    The bucket and endpoint are included because the most common cause is that
    one of them is simply wrong, and comparing them against the dashboard is a
    two-second check that is impossible without seeing what the service used.
    """
    parts = [type(exc).__name__]
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        code = error.get("Code")
        if code:
            parts.append(f"code={code}")
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if status:
            parts.append(f"http={status}")
    parts.append(f"bucket={settings.r2_bucket!r}")
    parts.append(f"endpoint={_endpoint_url()}")
    return " ".join(parts)


async def upload(local_path: str | Path, key: str) -> None:
    """Upload a finished render to R2 under `key`.

    ContentDisposition is set to attachment so the browser saves the file instead of
    trying to stream it inline — the user asked for a download, not a player. The
    filename we advertise is the R2 key's basename, which the job builds from a
    sanitised title (never from raw remote input).
    """
    path = Path(local_path)
    if not path.is_file():
        raise ApiError("internal", detail="upload source missing")

    size = path.stat().st_size
    extra: dict[str, Any] = {
        "ContentType": _content_type_for(key),
        "ContentDisposition": f'attachment; filename="{Path(key).name}"',
        # Belt and braces alongside the bucket lifecycle rule: nothing here is worth caching
        # at an edge because every object is single-use and short-lived.
        "CacheControl": "private, max-age=0, no-store",
    }

    try:
        async with _session.client("s3", **_client_kwargs()) as s3:  # type: ignore[call-overload]
            await s3.upload_file(str(path), settings.r2_bucket, key, ExtraArgs=extra)
    except Exception as exc:  # noqa: BLE001 - see below; every failure here is ours
        # Translated rather than allowed to escape, because the job's outermost
        # handler turns anything unrecognised into `internal` — the same code a
        # genuine crash produces. A wrong bucket name and a null-pointer bug then
        # look identical from the outside, which is exactly how a misconfigured
        # bucket survived a full debugging session.
        #
        # `_describe` is logged, never returned: it names the bucket and endpoint,
        # which are ours to know and not the caller's.
        log.error(
            "r2.upload_failed",
            extra={"key": key, "bytes": size, "error": _describe(exc)},
        )
        raise ApiError("storage_failed", detail="Could not store the finished file.") from exc

    log.info("r2.upload_ok", extra={"key": key, "bytes": size})


def presign(key: str, ttl_s: int) -> str:
    """Return a short-lived presigned GET URL for `key`.

    Sync on purpose: SigV4 presigning is HMAC over a canonical string, entirely local.
    Making it async would imply I/O that does not happen and would force every caller
    into an await for no reason.

    NOTE ON R2_PUBLIC_BASE: SigV4 signs the Host header, so a presigned URL cannot have
    its hostname rewritten to a custom domain after the fact — the signature would not
    verify. We therefore always sign the account endpoint. R2_PUBLIC_BASE is reserved for
    buckets that are deliberately public (thumbnail proxies and the like) and is never
    used to serve job results.
    """
    ttl = max(_MIN_PRESIGN_TTL_S, int(ttl_s))
    url: str = _get_signer().generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.r2_bucket, "Key": key},
        ExpiresIn=ttl,
    )
    return url


async def delete(key: str) -> None:
    """Best-effort delete.

    Called on the failure path so a half-uploaded object does not sit in the bucket
    until the lifecycle rule notices. A failure to delete must never turn an already
    failing job into a different error, so we swallow and log.
    """
    try:
        async with _session.client("s3", **_client_kwargs()) as s3:  # type: ignore[call-overload]
            await s3.delete_object(Bucket=settings.r2_bucket, Key=key)
        log.info("r2.delete_ok", extra={"key": key})
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the original error
        log.warning("r2.delete_failed", extra={"key": key, "error": type(exc).__name__})


async def health() -> bool:
    """Cheap readiness probe: can we talk to the bucket at all?"""
    try:
        async with _session.client("s3", **_client_kwargs()) as s3:  # type: ignore[call-overload]
            await asyncio.wait_for(s3.head_bucket(Bucket=settings.r2_bucket), timeout=5)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("r2.health_failed", extra={"error": _describe(exc)})
        return False
