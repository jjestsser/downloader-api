"""Tests for the configuration this service refuses to boot with.

The guard below exists because of one deploy. `.env` carries
`R2_ENDPOINT_URL_OVERRIDE=http://127.0.0.1:9000` so the upload path can be aimed
at docker-compose's MinIO. That file was copied wholesale into the platform's
variables, the override beat `R2_ACCOUNT_ID` exactly as designed, and inside the
container 127.0.0.1 is the container — so every upload hit a refused connection
and every download on the site failed.

Nothing caught it. `r2_configured` does not look at the override, so `/readyz`
answered `"r2": "configured"`. The job's outermost handler reported `internal`,
the same code a crash produces. The one honest signal, a refused TCP connection,
was three layers down.

`Settings` is instantiated per test here rather than imported, because the module
level singleton is built at import time and cannot be re-parameterised.
"""

from __future__ import annotations

import pytest

from app.settings import Settings

#: Enough to construct Settings without tripping the production secret guard.
BASE: dict[str, str] = {
    "redis_url": "redis://localhost:6379/0",
    "ticket_secret": "0123456789abcdef0123456789abcdef",
    "ip_salt": "0123456789abcdef",
    "turnstile_secret": "turnstile-secret-value",
    "allowed_origins": "https://kavithakanchana.me",
    "r2_account_id": "acct",
    "r2_access_key_id": "key",
    "r2_secret_access_key": "secret",
    "r2_bucket": "downloader-artifacts",
}

LOOPBACK = [
    "http://127.0.0.1:9000",
    "http://localhost:9000",
    "http://0.0.0.0:9000",
    "http://host.docker.internal:9000",
    "http://minio:9000",
]

DEPLOYED = ["production", "staging"]
LOCAL = ["development", "test"]


@pytest.mark.parametrize("environment", DEPLOYED)
@pytest.mark.parametrize("override", LOOPBACK)
def test_deployed_boot_is_refused_with_a_loopback_storage_endpoint(
    environment: str, override: str
) -> None:
    with pytest.raises(ValueError) as excinfo:
        Settings(_env_file=None, environment=environment, r2_endpoint_url_override=override, **BASE)

    message = str(excinfo.value)
    assert "R2_ENDPOINT_URL_OVERRIDE" in message
    # The message has to name the variable to delete. An operator reading a crash
    # loop at 2am should not have to grep the source to learn which one it is.
    assert "Delete the variable" in message


@pytest.mark.parametrize("environment", DEPLOYED)
def test_staging_is_guarded_exactly_like_production(environment: str) -> None:
    """`staging` is where this deployed first, and is what Railway actually sets.

    A guard keyed off `is_production` alone would have exempted the one
    environment the bug happened in.
    """
    settings = Settings(_env_file=None, environment=environment, **BASE)

    assert settings.is_deployed is True


@pytest.mark.parametrize("environment", LOCAL)
@pytest.mark.parametrize("override", LOOPBACK)
def test_local_development_may_point_at_minio(environment: str, override: str) -> None:
    """The override's entire reason for existing must keep working."""
    settings = Settings(
        _env_file=None, environment=environment, r2_endpoint_url_override=override, **BASE
    )

    assert settings.r2_endpoint_url == override


@pytest.mark.parametrize("environment", DEPLOYED)
def test_a_real_r2_endpoint_override_is_still_allowed_when_deployed(environment: str) -> None:
    """Only loopback is rejected. A custom S3-compatible host is a valid choice."""
    override = "https://storage.example.com"
    settings = Settings(
        _env_file=None, environment=environment, r2_endpoint_url_override=override, **BASE
    )

    assert settings.r2_endpoint_url == override


@pytest.mark.parametrize("environment", DEPLOYED)
def test_the_endpoint_is_derived_from_the_account_when_unset(environment: str) -> None:
    settings = Settings(_env_file=None, environment=environment, **BASE)

    assert settings.r2_endpoint_url == "https://acct.r2.cloudflarestorage.com"


@pytest.mark.parametrize("environment", DEPLOYED + LOCAL)
def test_error_detail_is_released_only_outside_production(environment: str) -> None:
    """`internal` says nothing on its own; the exception behind it says everything.

    Which is also why it stays in the building in production: it is a raw
    exception message and can carry paths, hostnames and URL fragments that a
    public endpoint has no business handing out.
    """
    settings = Settings(_env_file=None, environment=environment, **BASE)

    assert settings.is_production == (environment == "production")
