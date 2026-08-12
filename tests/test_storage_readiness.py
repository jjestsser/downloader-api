"""Tests for the two lies this service told about object storage.

Both regressions below shipped together and produced one symptom: every worker
download failed with `error_code: "internal"` while `/readyz` cheerfully reported
`"r2": "configured"`. Neither the API response nor the readiness probe pointed at
storage, so the actual cause — the bucket handoff — was the last place anyone
looked.

  1. `/readyz` reported R2 by checking that four environment variables were
     non-empty. A probe that cannot fail is not a probe. `r2.health()` already
     existed and did a real HeadBucket; nothing called it.

  2. `r2.upload()` let botocore exceptions escape into the job's outermost
     `except Exception`, which reports `internal` — the same code a genuine crash
     produces. A wrong bucket name and a null-pointer bug were indistinguishable.

Environment is populated before importing anything from `app` because
`app.settings` instantiates its `Settings` at import time.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("TICKET_SECRET", "unit-test-ticket-secret-do-not-ship")
os.environ.setdefault("IP_SALT", "unit-test-ip-salt")
os.environ.setdefault("ALLOWED_ORIGINS", "https://example.test")
os.environ.setdefault("R2_ACCOUNT_ID", "acct")
os.environ.setdefault("R2_ACCESS_KEY_ID", "key")
os.environ.setdefault("R2_SECRET_ACCESS_KEY", "secret")
os.environ.setdefault("R2_BUCKET", "bucket")
os.environ.setdefault("METRICS_TOKEN", "metrics")
os.environ.setdefault("DAILY_SPEND_CAP_MICRO_USD", "50000000")

from app.errors import ERROR_CODES, ApiError  # noqa: E402
from app.routes import health  # noqa: E402
from app.storage import r2  # noqa: E402

pytestmark = pytest.mark.asyncio


class _ClientError(Exception):
    """Shaped like botocore's ClientError, without the botocore import."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": "irrelevant"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


@pytest.fixture(autouse=True)
def _clear_probe_cache() -> None:
    """The probe caches for 30s; tests must not inherit each other's verdict."""
    health._r2_probe["at"] = 0.0
    health._r2_probe["why"] = None


# ---------------------------------------------------------------------------
# /readyz must actually probe
# ---------------------------------------------------------------------------


async def test_readyz_reports_r2_down_when_the_bucket_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression, exactly: env vars all set, bucket broken."""
    monkeypatch.setattr(r2, "health", lambda: _broken())

    assert (await health._r2_ready())[0] == "down"


async def test_readyz_reports_r2_up_when_the_bucket_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(r2, "health", lambda: _healthy())

    assert (await health._r2_ready())[0] == "up"


async def test_readyz_never_reports_the_old_configured_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`"configured"` meant "four strings are non-empty" and misled for a week.

    Asserted as a literal because the failure mode is someone reintroducing the
    cheap check for being cheap, and every other assertion here would still pass.
    """
    monkeypatch.setattr(r2, "health", lambda: _healthy())

    assert (await health._r2_ready())[0] != "configured"


async def test_r2_probe_is_cached_between_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """/readyz is polled by the platform; one HeadBucket per poll is waste."""
    calls = {"n": 0}

    async def counting() -> str | None:
        calls["n"] += 1
        return None

    monkeypatch.setattr(r2, "health", counting)

    for _ in range(5):
        assert (await health._r2_ready())[0] == "up"
    assert calls["n"] == 1


async def test_unconfigured_r2_is_not_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    """No credentials is a different state from bad credentials, and is not an error."""

    async def explode() -> str | None:  # pragma: no cover - must never run
        raise AssertionError("probed R2 with no credentials configured")

    monkeypatch.setattr(r2, "health", explode)
    monkeypatch.setattr(type(r2.settings), "r2_configured", property(lambda _: False))

    assert (await health._r2_ready())[0] == "unconfigured"


async def test_r2_readiness_does_not_take_the_service_out_of_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bucket outage must degrade this service, not remove it from rotation.

    `/v1/resolve` and every direct-CDN handoff work with R2 completely down, and
    those are the majority of requests. Returning 503 would take a mostly working
    service entirely offline.
    """
    monkeypatch.setattr(r2, "health", lambda: _broken())
    monkeypatch.setattr(health, "ping", _true)

    response = await health.readyz()

    assert response.status_code == 200
    assert b'"r2":"down"' in bytes(response.body).replace(b" ", b"")


# ---------------------------------------------------------------------------
# Upload failures must be their own error code
# ---------------------------------------------------------------------------


async def test_storage_failed_is_a_registered_code() -> None:
    assert "storage_failed" in ERROR_CODES


async def test_upload_translates_client_errors_into_storage_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The whole point: a bad bucket must not present as `internal`."""
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"not really an mp4")

    monkeypatch.setattr(
        r2, "_session", _SessionRaising(_ClientError("NoSuchBucket", 404))
    )

    with pytest.raises(ApiError) as excinfo:
        await r2.upload(source, "job/clip.mp4")

    assert excinfo.value.code == "storage_failed"


async def test_upload_still_reports_a_missing_source_as_internal(tmp_path: Path) -> None:
    """A source file that is not there is our bug, not the bucket's."""
    with pytest.raises(ApiError) as excinfo:
        await r2.upload(tmp_path / "absent.mp4", "job/absent.mp4")

    assert excinfo.value.code == "internal"


async def test_describe_names_the_failure_without_leaking_the_secret() -> None:
    """`type(exc).__name__` alone ruled nothing out; the S3 code does.

    botocore raises ClientError for a missing bucket, wrong credentials, a
    signature mismatch and a permissions denial alike.
    """
    described = r2._describe(_ClientError("InvalidAccessKeyId", 403))

    assert "InvalidAccessKeyId" in described
    assert "http=403" in described
    assert "bucket=" in described
    assert os.environ["R2_SECRET_ACCESS_KEY"] not in described


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _true() -> bool:
    return True


async def _healthy() -> str | None:
    """`r2.health` returns None when the bucket answers."""
    return None


async def _broken() -> str | None:
    return "ClientError code=NoSuchBucket http=404 bucket='wrong' endpoint=https://acct.r2.cloudflarestorage.com"


class _SessionRaising:
    """An aioboto3 session whose client raises on `upload_file`."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def client(self, *_args: object, **_kwargs: object) -> _SessionRaising:
        return self

    async def __aenter__(self) -> _SessionRaising:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def upload_file(self, *_args: object, **_kwargs: object) -> None:
        raise self._exc


# ---------------------------------------------------------------------------
# /readyz must probe the scratch directory too
# ---------------------------------------------------------------------------


async def test_scratch_is_reported_unwritable_when_it_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A read-only or root-owned mount is the other way every job dies at once.

    `download_job` starts by creating a subdirectory of SCRATCH_DIR. When that
    fails, the job reports `internal` and every other signal stays green: the API
    answers, Redis is up, `/v1/resolve` works — none of them write a file.
    """
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    monkeypatch.setattr(
        health, "settings", health.settings.model_copy(update={"scratch_dir": str(locked)})
    )

    assert health._scratch_ready() == "unwritable"


async def test_scratch_is_reported_writable_and_leaves_nothing_behind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The probe must not accumulate a directory per poll."""
    monkeypatch.setattr(
        health, "settings", health.settings.model_copy(update={"scratch_dir": str(tmp_path)})
    )

    assert health._scratch_ready() == "writable"
    assert list(tmp_path.iterdir()) == []


async def test_readyz_publishes_why_r2_is_down_outside_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """"down" alone still costs a trip to the host's logs.

    The reason names the bucket and the endpoint, which are the two things that
    are usually wrong.
    """
    monkeypatch.setattr(r2, "health", lambda: _broken())
    monkeypatch.setattr(
        health, "settings", health.settings.model_copy(update={"environment": "staging"})
    )

    state, why = await health._r2_ready()

    assert state == "down"
    assert why is not None and "NoSuchBucket" in why


async def test_readyz_withholds_the_reason_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It is ours to know: it names our bucket and our endpoint."""
    monkeypatch.setattr(r2, "health", lambda: _broken())
    monkeypatch.setattr(
        health, "settings", health.settings.model_copy(update={"environment": "production"})
    )

    state, why = await health._r2_ready()

    assert state == "down"
    assert why is None
