"""
backend/main.py
─────────────────────────────────────────────────────────────────────────────
FastAPI application entry point.

PURPOSE:
  Creates, configures, and exports the FastAPI application instance. This is
  the single file that wires everything together: settings → logging →
  middleware → dependency initialisation → routers → exception handlers.

DESIGN DECISIONS:
  1. The `lifespan` async context manager (FastAPI 0.93+) replaces the
     deprecated `on_startup` / `on_shutdown` event hooks. It guarantees
     symmetric setup/teardown and makes resource lifecycle explicit and
     auditable. Every resource acquired in the `async with` block is
     guaranteed to be released on shutdown, even on unhandled exceptions.
  2. Application construction is split into small, focused functions
     (`_create_app`, `_register_routers`, `_register_exception_handlers`)
     rather than a flat procedural sequence. Each function is independently
     readable and, where needed, testable.
  3. The `app` module-level variable is the single FastAPI instance used
     by uvicorn. `uvicorn.run(app)` in the `if __name__ == "__main__"` block
     enables `python -m backend.main` as a dev server launch command.
  4. Exception handlers return structured JSON error responses with a
     consistent shape: `{error, message, request_id}`. The `request_id`
     is pulled from `request.state` (set by `RequestIDMiddleware`) to enable
     log correlation across the request lifecycle.
  5. The 500 handler deliberately omits the internal exception detail from
     the response body — it logs it server-side only. This prevents leaking
     stack traces, internal paths, or data model details to clients.

BUG FIX (data_dir):
  The original lifespan computed:
      data_dir = os.path.dirname(settings.database_url)
  For `:memory:` (test DB), `database_url` returns `:memory:` and
  `os.path.dirname(":memory:")` returns `""`. Calling `os.makedirs("")`
  raises `FileNotFoundError`. Fixed by checking `data_dir` truthiness AND
  `database_url != ":memory:"` before calling makedirs. database.py has its
  own guarded makedirs call; main.py's call is a belt-and-suspenders check.

FUTURE SCALABILITY:
  - Add `set_rate_limiter(AsyncLimiter(...))` in lifespan when blockchain
    layer ships.
  - Add `init_session_manager()` in lifespan when agent layer ships.
  - Add WebSocket router registration when agent layer ships.
  - No changes needed to the app factory or middleware stack.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from backend.agent.session_manager import init_session_manager, close_session_manager

from aiolimiter import AsyncLimiter
import structlog
import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.api.middleware import register_middleware
from backend.api.routers import health_router
from backend.constants import AGENT_VERSION
from backend.dependencies import close_http_client, init_http_client, set_rate_limiter
from backend.exceptions import BaseApplicationException, HTTPAwareException
from backend.logging_config import configure_logging
from backend.persistence.database import close_db, init_db
from backend.settings import get_settings

# ─────────────────────────────────────────────────────────────────────────────
# Logger — obtained after configure_logging() is called in lifespan
# ─────────────────────────────────────────────────────────────────────────────
logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan context manager
# ─────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage application startup and shutdown lifecycle.

    Everything before `yield` runs on startup.
    Everything after `yield` runs on shutdown (guaranteed even on crash).

    Startup sequence:
        1. Configure logging (must be first — all subsequent steps log)
        2. Load and validate settings
        3. Ensure data directory exists (skipped for :memory:)
        4. Initialise database connection and run migrations
        5. Initialise shared HTTP client
        6. Log startup summary

    Shutdown sequence:
        1. Close database connection
        2. Close shared HTTP client (drains connection pool)
        3. Log shutdown confirmation
    """
    # ── STARTUP ───────────────────────────────────────────────────────────────

    # Step 1: Logging must come first so all subsequent logs are structured
    configure_logging()

    # Step 2: Load and validate settings (raises on misconfiguration)
    settings = get_settings()
    from backend.utils import mask_api_key
    logger.info(
        "config_debug",
        etherscan_key=mask_api_key(settings.etherscan.api_key),
        etherscan_base_url=settings.etherscan.base_url,
        gemini_key=mask_api_key(settings.llm.google_api_key),
    )
    logger.info(
        "application_starting",
        name=settings.app.name,
        version=settings.app.version,
        agent_version=AGENT_VERSION,
        environment=settings.app.env,
        debug=settings.app.debug,
        api_prefix=settings.api.prefix,
        host=settings.api.host,
        port=settings.api.port,
    )

    # Step 3: Ensure the data directory exists for file-based SQLite databases.
    # BUG FIX: database_url returns ":memory:" for test/in-memory configs.
    # os.path.dirname(":memory:") == "" — calling os.makedirs("") raises
    # FileNotFoundError. Guard with both truthiness check AND memory check.
    db_url = settings.database_url
    if db_url != ":memory:":
        data_dir = os.path.dirname(db_url)
        if data_dir:
            os.makedirs(data_dir, exist_ok=True)
            logger.debug("data_directory_ready", path=data_dir)

    # Step 4: Initialise database (open connection, PRAGMAs, migrations)
    await init_db()
    logger.info("database_initialised")

    # Step 5: Initialise shared HTTP client
    await init_http_client(settings)
    logger.info("http_client_initialised")

    # ── Phase 2: rate limiter ─────────────────────────────────────────────────
    from backend.blockchain.rate_limiter import create_rate_limiter
    limiter = create_rate_limiter(settings)
    set_rate_limiter(limiter)
    logger.info("rate_limiter_initialised",
                rps=settings.rate_limiter.requests_per_second,
                burst=settings.rate_limiter.burst_capacity)
 
    # ── Future startup steps ──────────────────────────────────────────────────
    # await init_session_manager(settings)  # agent layer
    from backend.agent.session_manager import init_session_manager
    init_session_manager()
    logger.info("session_manager_initialised")
    #logger.info("application_ready", status="ok")

    # ── HAND CONTROL TO THE APPLICATION ───────────────────────────────────────
    yield

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────

    logger.info("application_shutting_down")

    # Close database first (flush any pending writes)
    await close_db()
    logger.info("database_closed")

    await close_http_client()
    logger.info("http_client_closed")

    # ── Future shutdown steps ─────────────────────────────────────────────────
    # await close_session_manager()
    from backend.agent.session_manager import close_session_manager
    await close_session_manager()
    logger.info("session_manager_closed")
    #logger.info("application_stopped")


# ─────────────────────────────────────────────────────────────────────────────
# Exception handlers
# ─────────────────────────────────────────────────────────────────────────────


async def _application_exception_handler(
    request: Request, exc: BaseApplicationException
) -> JSONResponse:
    """
    Handle domain exceptions from the application exception hierarchy.

    Converts BaseApplicationException (and all subclasses) to structured JSON.
    HTTPAwareException subclasses carry their own http_status_code; all other
    application exceptions default to 500.
    """
    request_id = getattr(request.state, "request_id", "unknown")

    http_status = (
        exc.http_status_code  # type: ignore[attr-defined]
        if isinstance(exc, HTTPAwareException)
        else status.HTTP_500_INTERNAL_SERVER_ERROR
    )

    logger.warning(
        "application_exception",
        request_id=request_id,
        path=request.url.path,
        method=request.method,
        error_code=exc.error_code.value,
        message=exc.message,
        context=exc.context,
        http_status=http_status,
    )

    return JSONResponse(
        status_code=http_status,
        content={
            "error": exc.error_code.value,
            "message": exc.message,
            "request_id": request_id,
            "context": exc.context,
            "timestamp": exc.timestamp,
        },
    )


async def _validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Handle Pydantic validation errors from request body/query parsing.

    Returns HTTP 422 with a structured list of field-level errors. The error
    detail is safe to return to clients — it describes the request shape
    problem without leaking internal state.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    errors = exc.errors()

    logger.warning(
        "request_validation_error",
        request_id=request_id,
        path=request.url.path,
        method=request.method,
        error_count=len(errors),
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "The request body or parameters did not pass validation.",
            "request_id": request_id,
            "details": [
                {
                    "field": " → ".join(str(loc) for loc in e["loc"]),
                    "message": e["msg"],
                    "type": e["type"],
                }
                for e in errors
            ],
        },
    )


async def _http_exception_handler(request: Request, exc: Any) -> JSONResponse:
    """
    Handle HTTPExceptions raised by route handlers and dependencies.

    Wraps FastAPI's default handler to ensure a consistent error response
    shape with `request_id` for log correlation.
    """
    request_id = getattr(request.state, "request_id", "unknown")

    logger.info(
        "http_exception",
        request_id=request_id,
        path=request.url.path,
        method=request.method,
        status_code=exc.status_code,
        detail=exc.detail,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": _status_to_label(exc.status_code),
            "message": exc.detail
            if isinstance(exc.detail, str)
            else exc.detail.get("message", str(exc.detail)),
            "request_id": request_id,
            **(
                {"details": exc.detail}
                if isinstance(exc.detail, dict)
                else {}
            ),
        },
    )


async def _unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """
    Handle any unhandled exceptions that escape route handlers.

    Logs the full traceback server-side. Returns a generic 500 to the client
    — internal exception detail is deliberately NOT included in the response
    to prevent information leakage.
    """
    request_id = getattr(request.state, "request_id", "unknown")

    logger.exception(
        "unhandled_exception",
        request_id=request_id,
        path=request.url.path,
        method=request.method,
        exc_info=exc,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": (
                "An unexpected error occurred. "
                "Please report this with your request_id."
            ),
            "request_id": request_id,
        },
    )


def _status_to_label(code: int) -> str:
    """Map an HTTP status code to a human-readable label."""
    labels = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }
    return labels.get(code, f"HTTP {code}")


# ─────────────────────────────────────────────────────────────────────────────
# Router registration
# ─────────────────────────────────────────────────────────────────────────────


def _register_routers(app: FastAPI, api_prefix: str) -> None:
    """
    Mount all API routers onto the application.

    Args:
        app: FastAPI application instance.
        api_prefix: The global API prefix (e.g., "/api/v1").
    """
    # ── Operations (no auth — monitoring infrastructure needs these) ──────────
    app.include_router(health_router, prefix=api_prefix)

     # ── Phase 2 routers ───────────────────────────────────────────────────────
    from backend.api.routers.investigation import router as investigation_router
    from backend.api.routers.history import router as history_router
    from backend.api.routers.report import router as report_router
    from backend.api.routers.graph import router as graph_router
 
    app.include_router(investigation_router, prefix=api_prefix)
    app.include_router(history_router, prefix=api_prefix)
    app.include_router(report_router, prefix=api_prefix)
    app.include_router(graph_router, prefix=api_prefix)


def _register_exception_handlers(app: FastAPI) -> None:
    """
    Register all exception handlers on the application.

    Registration order matters: more specific handlers must be registered
    before more general ones. BaseApplicationException is registered before
    the catch-all Exception handler.

    Args:
        app: FastAPI application instance.
    """
    from fastapi.exceptions import HTTPException

    app.add_exception_handler(
        BaseApplicationException,  # type: ignore[arg-type]
        _application_exception_handler,
    )
    app.add_exception_handler(
        RequestValidationError,
        _validation_exception_handler,  # type: ignore[arg-type]
    )
    app.add_exception_handler(HTTPException, _http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, _unhandled_exception_handler)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# Application factory
# ─────────────────────────────────────────────────────────────────────────────


def _create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Returns the fully configured application instance. Separated from the
    module-level `app = _create_app()` call so the factory can be called
    in tests with overrides applied before the instance is returned.

    Returns:
        Configured FastAPI instance ready for mounting by uvicorn.
    """
    settings = get_settings()

    application = FastAPI(
        title=settings.app.name,
        version=settings.app.version,
        description=(
            "Single-Agent Blockchain Investigator — "
            "AI-powered forensic analysis of Ethereum wallet activity. "
            "Detects suspicious transaction patterns using a structured "
            "LangGraph agent, deterministic rule engine, and three-layer "
            "trace selection intelligence."
        ),
        docs_url=f"{settings.api.prefix}/docs" if settings.app.debug else None,
        redoc_url=f"{settings.api.prefix}/redoc" if settings.app.debug else None,
        openapi_url=f"{settings.api.prefix}/openapi.json",
        lifespan=lifespan,
        # Disable FastAPI's default exception handler wrapping so our
        # custom handlers have full control
        separate_input_output_schemas=False,
    )

    # Order matters: middleware first, then exception handlers, then routers
    register_middleware(application)
    _register_exception_handlers(application)
    _register_routers(application, api_prefix=settings.api.prefix)

    return application


# ─────────────────────────────────────────────────────────────────────────────
# Application instance — used by uvicorn
# ─────────────────────────────────────────────────────────────────────────────

app = _create_app()


# ─────────────────────────────────────────────────────────────────────────────
# Dev server entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _settings = get_settings()

    uvicorn.run(
        "backend.main:app",
        host=_settings.api.host,
        port=_settings.api.port,
        reload=_settings.api.reload,
        workers=_settings.api.workers if not _settings.api.reload else 1,
        log_level=_settings.logging.level.lower(),
        # Disable uvicorn's default access log — our middleware handles it
        access_log=False,
    )