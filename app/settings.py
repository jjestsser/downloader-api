"""Runtime configuration for the downloader service.

WHY this module refuses to be lenient: every abuse control in this service is
anchored to two secrets. `TICKET_SECRET` is the only thing standing between
"our front-end can call /v1/resolve" and "the entire internet can call
/v1/resolve", and `IP_SALT` is the only thing that keeps the per-IP quota keys
from being a reversible rainbow table of everyone who used the site. A process
that boots with either of them empty is not a degraded service, it is an open
relay with a bill attached. So the model validator raises at import time in
production and the container crash-loops loudly instead of serving.

Outside production the same validator stays quiet, because tests and local
development must be able to `from app.settings import settings` without a
secrets file.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["production", "staging", "development", "test"]

#: Values people type when they mean "I'll fill this in later". Treated as unset.
_PLACEHOLDER_SECRETS: Final[frozenset[str]] = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "change_me",
        "secret",
        "supersecret",
        "placeholder",
        "todo",
        "xxx",
        "test",
        "dev",
        "none",
        "null",
        "undefined",
    }
)

#: Fields whose values must never reach a log line, a traceback frame dump or a
#: `repr(settings)` in an error report. Masked by `__repr_args__` below.
SECRET_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "redis_url",
        "ticket_secret",
        "ip_salt",
        "turnstile_secret",
        "r2_access_key_id",
        "r2_secret_access_key",
        "metrics_token",
        "proxy_datacenter_url",
        "proxy_residential_url",
    }
)

_MIN_TICKET_SECRET_LEN: Final[int] = 32
_MIN_IP_SALT_LEN: Final[int] = 16


class Settings(BaseSettings):
    """Every environment variable the service reads, with production guards."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # --- runtime -----------------------------------------------------------
    environment: Environment = "production"
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = "INFO"

    # --- infrastructure ----------------------------------------------------
    redis_url: str = "redis://127.0.0.1:6379/0"

    # --- ticket + identity hashing ----------------------------------------
    ticket_secret: str = ""
    ip_salt: str = ""
    turnstile_secret: str = ""

    # WHY a raw CSV string rather than list[str]: pydantic-settings JSON-decodes
    # complex-typed fields straight out of the environment, so a plain
    # `ALLOWED_ORIGINS=https://a.com,https://b.com` would blow up before any
    # validator could normalise it. Parsed by `cors_origins` instead.
    allowed_origins: str = ""

    # --- object storage (R2) ----------------------------------------------
    # Explicit S3 endpoint override. Empty in production, where the endpoint is
    # derived from `r2_account_id`. Set it to point the same code path at a local
    # MinIO (see docker-compose.yml) so the worker's upload/presign path can be
    # tested end to end without touching Cloudflare.
    r2_endpoint_url_override: str = ""
    r2_account_id: str = ""
    r2_access_key_id: str = ""
    r2_secret_access_key: str = ""
    r2_bucket: str = ""
    r2_public_base: str = ""

    # --- limits ------------------------------------------------------------
    max_duration_s: int = Field(default=3600, gt=0)
    max_filesize_mb: int = Field(default=500, gt=0)
    resolve_quota_per_day: int = Field(default=30, gt=0)
    bytes_quota_gb_per_day: float = Field(default=2.0, gt=0)
    daily_spend_cap_micro_usd: int = Field(default=5_000_000, gt=0)
    result_ttl_s: int = Field(default=21_600, ge=60)

    # --- filesystem --------------------------------------------------------
    # The one writable directory. `/scratch` in the container (see Dockerfile);
    # overridden locally because the host has no such path. This belongs here
    # rather than in `os.environ.get(...)` at a module scope somewhere: a
    # setting read directly from the environment is invisible to `.env`, so it
    # silently keeps its default and the failure surfaces far from the cause.
    scratch_dir: str = "/scratch"

    # --- ops ---------------------------------------------------------------
    metrics_token: str = ""

    # --- egress proxies (credentials live in the URL userinfo) -------------
    proxy_datacenter_url: str | None = None
    proxy_residential_url: str | None = None

    # ------------------------------------------------------------------ #
    # normalisation
    # ------------------------------------------------------------------ #

    @field_validator(
        "redis_url",
        "ticket_secret",
        "ip_salt",
        "turnstile_secret",
        "allowed_origins",
        "r2_account_id",
        "r2_access_key_id",
        "r2_secret_access_key",
        "r2_bucket",
        "r2_public_base",
        "metrics_token",
        "log_level",
        mode="before",
    )
    @classmethod
    def _strip(cls, value: object) -> object:
        """Railway variable editors love trailing whitespace; it breaks HMAC."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("proxy_datacenter_url", "proxy_residential_url", mode="before")
    @classmethod
    def _empty_proxy_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("r2_public_base")
    @classmethod
    def _no_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, value: str) -> str:
        return (value or "INFO").upper()

    # ------------------------------------------------------------------ #
    # derived views
    # ------------------------------------------------------------------ #

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cors_origins(self) -> list[str]:
        """ALLOWED_ORIGINS parsed into the exact strings a browser sends.

        Origins are compared byte-for-byte by CORSMiddleware, and a browser
        never sends a trailing slash, so one is stripped here.
        """
        return [o.strip().rstrip("/") for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def max_filesize_bytes(self) -> int:
        return self.max_filesize_mb * 1024 * 1024

    @property
    def bytes_quota_per_day(self) -> int:
        return int(self.bytes_quota_gb_per_day * 1024**3)

    @property
    def r2_configured(self) -> bool:
        """Worker downloads need R2; direct CDN handoff does not."""
        return bool(
            self.r2_account_id
            and self.r2_access_key_id
            and self.r2_secret_access_key
            and self.r2_bucket
        )

    @property
    def r2_endpoint_url(self) -> str:
        # An explicit override wins so the same client can be aimed at MinIO
        # locally; production leaves it empty and derives the R2 endpoint.
        return (
            self.r2_endpoint_url_override
            or f"https://{self.r2_account_id}.r2.cloudflarestorage.com"
        )

    @property
    def metrics_enabled(self) -> bool:
        return bool(self.metrics_token) or not self.is_production

    # ------------------------------------------------------------------ #
    # production guard
    # ------------------------------------------------------------------ #

    @model_validator(mode="after")
    def _fail_fast_in_production(self) -> Settings:
        if not self.is_production:
            return self

        problems: list[str] = []

        if self.ticket_secret.lower() in _PLACEHOLDER_SECRETS or len(self.ticket_secret) < _MIN_TICKET_SECRET_LEN:
            problems.append(
                f"TICKET_SECRET must be at least {_MIN_TICKET_SECRET_LEN} random characters "
                "(`openssl rand -hex 32`). Without it every ticket signature is forgeable "
                "and /v1/resolve is an open endpoint."
            )

        if self.ip_salt.lower() in _PLACEHOLDER_SECRETS or len(self.ip_salt) < _MIN_IP_SALT_LEN:
            problems.append(
                f"IP_SALT must be at least {_MIN_IP_SALT_LEN} random characters. Without it the "
                "quota keys are unsalted SHA-256 of an IPv4 address, which is trivially reversible."
            )

        if self.turnstile_secret.lower() in _PLACEHOLDER_SECRETS:
            problems.append(
                "TURNSTILE_SECRET is unset; ticket issuance would have no human check in front of it."
            )

        origins = self.cors_origins
        if not origins:
            problems.append("ALLOWED_ORIGINS is empty; no browser origin would be able to call the API.")
        if "*" in origins:
            problems.append(
                "ALLOWED_ORIGINS contains '*'. This service is called by one known front-end; "
                "list its origins explicitly."
            )
        for origin in origins:
            if not origin.startswith(("http://", "https://")):
                problems.append(f"ALLOWED_ORIGINS entry {origin!r} is not a scheme-qualified origin.")

        if not self.redis_url:
            problems.append("REDIS_URL is unset; tickets, quotas and the killswitch all live in Redis.")

        if problems:
            raise ValueError(
                "Refusing to start in production with an unsafe configuration:\n  - "
                + "\n  - ".join(problems)
            )
        return self

    # ------------------------------------------------------------------ #

    def __repr_args__(self):  # type: ignore[override]
        """Mask secrets so an accidental `repr(settings)` cannot leak them."""
        for key, value in super().__repr_args__():
            yield key, ("***" if key in SECRET_FIELDS and value else value)


#: Module-level singleton. Importing this module IS the configuration check.
settings = Settings()
