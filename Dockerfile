# syntax=docker/dockerfile:1.7
#
# Two stages. The builder owns uv and a compiler-capable environment; the runtime image
# carries only the venv, ffmpeg, and a user that cannot write to anything that executes.

ARG PYTHON_VERSION=3.12-slim-bookworm
ARG UV_VERSION=0.9.7

# ---------------------------------------------------------------------------
# Stage 1 — build the virtualenv
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS builder

ARG UV_VERSION
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Dependency layer first so source edits do not re-resolve the whole tree.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project

# Then the project itself.
COPY README.md ./
COPY app ./app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

# For byte-reproducible builds: commit uv.lock, add it to the COPY above, and swap both
# syncs to `uv sync --frozen ...`. Left off by default so a fresh clone builds without
# a lock present.

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS runtime

# Every package here is justified; nothing else gets in.
#   ffmpeg          — muxing. YouTube serves video and audio as separate DASH streams; without
#                     ffmpeg the worker path cannot produce a single playable file at all.
#   ca-certificates — TLS trust store for CDN fetches, R2 uploads, and Turnstile verification.
#                     python:slim ships one, but it drifts; refreshing it here is cheap insurance.
#   tini            — PID 1. ffmpeg is spawned per job and reaped by tini instead of accumulating
#                     zombies until the container hits its pid limit.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
        ffmpeg \
        ca-certificates \
        tini \
 && rm -rf /var/lib/apt/lists/*

# uid/gid 10001: high, fixed, and outside the host's normal user range so a bind mount
# escape lands on a uid that owns nothing. No home directory, no login shell.
RUN groupadd --system --gid 10001 app \
 && useradd  --system --uid 10001 --gid 10001 \
             --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=root:root /opt/venv /opt/venv
COPY --from=builder --chown=root:root /build/app /app/app
COPY --chown=root:root Procfile /app/Procfile

# Application code and interpreter are root-owned and unwritable by anyone. A worker
# process that gets compromised mid-download cannot rewrite the code that runs next boot.
RUN chmod -R a-w /app /opt/venv

# The one writable path in the image. 0700, owned by the app user, and on Railway it is
# ephemeral local disk (or a mounted volume — see README).
RUN install -d -m 0700 -o 10001 -g 10001 /scratch

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    # TMPDIR, HOME and the cache dir all point at the only writable mount: yt-dlp, ffmpeg
    # and tempfile.* would otherwise try /tmp or ~ and die on a read-only rootfs.
    TMPDIR=/scratch \
    HOME=/scratch \
    XDG_CACHE_HOME=/scratch/.cache \
    ENVIRONMENT=production \
    PORT=8080

# Deliberately NOT set: PYTHONPATH pointing at a writable directory. It would allow a
# hot yt-dlp patch without a rebuild, but it also puts an attacker-writable directory on
# sys.path, and this service writes attacker-influenced files for a living. The extractor
# update path is a nightly image rebuild instead (see README, "what breaks").

USER 10001:10001
WORKDIR /app
EXPOSE 8080
STOPSIGNAL SIGTERM

# Compose/local only — Railway uses the healthcheckPath in railway.json. Uses stdlib so
# the image does not have to carry curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz', timeout=4).status==200 else 1)"]

# -g forwards signals to the whole process group so honcho's children (uvicorn, arq, any
# in-flight ffmpeg) all get SIGTERM, not just PID 1.
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["honcho", "start", "-f", "/app/Procfile"]
