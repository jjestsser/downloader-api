"""FastAPI application wiring.

Composition only: no business logic lives here. What it does own is the four
things that are wrong-by-default in a fresh FastAPI app and would each be a
security or cost incident in this particular service —

  1. CORS locked to ALLOWED_ORIGINS (a wildcard would let any site spend our
     egress budget with a ticket lifted from ours),
  2. an exception wall so no traceback, URL or proxy credential ever reaches a
     response body,
  3. a lifespan that owns the Redis pool and the platform health canary,
  4. OpenAPI turned off in production, because the schema is a map of the abuse
     controls and nothing but our own front-end is meant to call this.
"""

from __future__ import annotations

import asyncio
import importlib
import random
import time
import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.errors import ApiError, api_error_handler
from app.jobs.queue import close_arq
from app.logging_conf import log, setup_logging
from app.redis_conn import close_redis, get_redis
from app.routes.health import router as health_router
from app.settings import settings

__version__: Final[str] = "1.0.0"
SERVICE_NAME: Final[str] = "downloader"

#: Every 30 minutes, per the operating rule: two consecutive canary failures
#: flip a platform to degraded so users get "TikTok is temporarily down"
#: instead of a stack trace when an extractor breaks.
CANARY_INTERVAL_S: Final[int] = 1800
CANARY_FIRST_RUN_DELAY_S: Final[int] = 20

#: Routers owned by other modules. Missing one in production is fatal.
OPTIONAL_ROUTER_MODULES: Final[tuple[str, ...]] = ("app.routes.resolve", "app.routes.jobs")

setup_logging()


# --------------------------------------------------------------------------- #
# Background: platform health canary
# --------------------------------------------------------------------------- #


async def _canary_loop() -> None:
    """Run the per-platform canary forever, swallowing every failure.

    WHY it never re-raises: this task is the thing that detects breakage. If it
    dies on the first transient error it stops being a detector exactly when it
    is needed, and the service happily keeps serving 502s from a broken
    extractor.
    """
    # `run_canary_once`, not `run_canary`: the canary module's `run_canary` is
    # itself a forever-loop. Calling it from inside this loop nested one loop in
    # another, so the inner one ran until the 900s timeout killed it, logged the
    # TimeoutError as `canary_failed`, and never once reached `canary_ok`.
    # Supervision (timeout, jitter, restart-on-error) belongs here; a single
    # sweep belongs there.
    try:
        run_canary_once = importlib.import_module("app.resolver.canary").run_canary_once
    except Exception:
        log.critical("canary_unavailable", exc_info=True)
        return

    await asyncio.sleep(CANARY_FIRST_RUN_DELAY_S)
    while True:
        started = time.monotonic()
        try:
            async with asyncio.timeout(CANARY_INTERVAL_S // 2):
                await run_canary_once()
            log.info("canary_ok", duration_ms=int((time.monotonic() - started) * 1000))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("canary_failed", exc_info=True)
        # Jitter keeps several instances from probing every platform in lockstep.
        await asyncio.sleep(CANARY_INTERVAL_S + random.uniform(0, 60))


# --------------------------------------------------------------------------- #
# Lifespan
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging()
    log.info(
        "startup",
        version=__version__,
        env=settings.environment,
        r2_configured=settings.r2_configured,
        origins=len(settings.cors_origins),
    )

    # Warm the pool, but do not block startup on it: /readyz already reports
    # Redis health, and a container that refuses to boot during a Redis blip
    # cannot come back when Redis does.
    try:
        client = await get_redis()
        await client.ping()
        log.info("redis_ready")
    except Exception:
        log.error("redis_unavailable_at_startup", exc_info=True)

    canary_task = asyncio.create_task(_canary_loop(), name="platform-canary")
    try:
        yield
    finally:
        canary_task.cancel()
        try:
            await canary_task
        except (asyncio.CancelledError, Exception):
            pass
        # The Turnstile verifier holds a module-level httpx.AsyncClient; without
        # this the connection pool leaks on every reload.
        try:
            from app.security.turnstile import aclose_turnstile_client

            await aclose_turnstile_client()
        except Exception:
            log.warning("turnstile_client_close_failed", exc_info=True)
        await close_arq()
        await close_redis()
        log.info("shutdown")


# --------------------------------------------------------------------------- #
# Exception handlers
# --------------------------------------------------------------------------- #


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """422 for malformed request bodies, with the offending values stripped.

    WHY the stripping: pydantic's error list echoes the rejected `input` back to
    the caller, and the rejected input here is a media URL. That would put the
    URL in a response body and, via any error-tracking middleware, into a log.
    Only the field location and the reason survive.
    """
    details: list[dict[str, Any]] = []
    if isinstance(exc, RequestValidationError):
        for err in exc.errors()[:10]:
            details.append(
                {
                    "loc": [str(part) for part in err.get("loc", ())],
                    "type": str(err.get("type", "value_error")),
                    "msg": str(err.get("msg", "invalid value")),
                }
            )
    return JSONResponse(
        status_code=422,
        content={"error": "invalid_request", "detail": "Request body failed validation.", "fields": details},
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Normalise Starlette's 404/405/etc into our `{error, detail}` shape."""
    status = getattr(exc, "status_code", 500)
    code = {404: "not_found", 405: "method_not_allowed", 429: "quota_exceeded"}.get(status, "http_error")
    detail = getattr(exc, "detail", None)
    return JSONResponse(
        status_code=status,
        content={"error": code, "detail": str(detail) if isinstance(detail, str) else "Request failed."},
        headers=getattr(exc, "headers", None),
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last line of defence: log the traceback, tell the client nothing.

    The response carries CORS headers, which it has to add for itself.

    Starlette runs this handler inside `ServerErrorMiddleware`, which sits
    *outside* every user middleware — CORSMiddleware included. So a 500 from
    here reached the browser with no `Access-Control-Allow-Origin`, the browser
    refused to expose it to script, and `fetch` rejected with a bare network
    error. The client could not tell a crashed request from an unplugged cable,
    and rendered "the downloader could not be reached" over a service that was
    up and answering.

    That cost real debugging time: job creation was failing with a genuine
    exception, logged here in full, while the page blamed the network.
    `ApiError` responses never had this problem — they are raised inside the
    stack and CORSMiddleware decorates them on the way out.

    The origin is echoed only when it is one we already allow, so this adds no
    permission CORSMiddleware would not have granted.
    """
    log.error(
        "unhandled_exception",
        route=getattr(getattr(request, "scope", {}).get("route", None), "path", request.url.path),
        request_id=getattr(request.state, "request_id", None),
        exc_info=True,
    )

    headers: dict[str, str] = {}
    origin = request.headers.get("origin", "")
    if origin and origin in settings.cors_origins:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Vary"] = "Origin"

    return JSONResponse(
        status_code=500,
        content={"error": "internal", "detail": "Something went wrong on our side."},
        headers=headers,
    )


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #


def _wire_routers(app: FastAPI) -> None:
    app.include_router(health_router)

    missing: list[str] = []
    for module_path in OPTIONAL_ROUTER_MODULES:
        try:
            module = importlib.import_module(module_path)
            app.include_router(module.router)
        except Exception:
            log.critical("router_import_failed", module=module_path, exc_info=True)
            missing.append(module_path)

    if missing and settings.is_production:
        # Booting a half-wired API in production would return 404 for /v1/resolve
        # and look like a client bug for hours. Crash-loop instead.
        raise RuntimeError(f"Refusing to start: routers failed to import: {', '.join(missing)}")


def create_app() -> FastAPI:
    docs_enabled = not settings.is_production
    app = FastAPI(
        title="Media Downloader API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_origin_regex=None,
        allow_credentials=False,  # tickets travel in a header; no cookies, ever
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Download-Ticket", "X-Turnstile-Token"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Correlation id + timing.

        Logs the matched route template, never `request.url`: the query string is
        attacker-controlled and the whole point is that we do not keep a record
        of what anyone downloaded.
        """
        request_id = uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.error(
                "request_failed",
                request_id=request_id,
                method=request.method,
                path=request.scope.get("path", ""),
                duration_ms=int((time.perf_counter() - started) * 1000),
                exc_info=True,
            )
            raise
        duration_ms = int((time.perf_counter() - started) * 1000)
        response.headers["X-Request-ID"] = request_id
        if request.scope.get("path", "") not in ("/healthz", "/readyz", "/metrics"):
            log.info(
                "request",
                request_id=request_id,
                method=request.method,
                path=request.scope.get("path", ""),
                status=response.status_code,
                duration_ms=duration_ms,
            )
        return response

    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    _wire_routers(app)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        """Deliberately boring: name and version, nothing operational."""
        return {"service": SERVICE_NAME, "version": __version__}

    return app


app = create_app()
