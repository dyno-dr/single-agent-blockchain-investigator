"""
backend/api/middleware.py
─────────────────────────────────────────────────────────────────────────────
FastAPI middleware stack registration and custom middleware implementations.

PURPOSE:
  All middleware is registered in one place and applied in a deliberate order.
  Middleware concerns: CORS, request ID injection, request/response logging,
  and process-time header attachment.

DESIGN DECISIONS:
  1. Middleware is registered via a `register_middleware(app)` function called
     from `main.py`. This keeps `main.py` clean and makes the middleware
     stack independently readable and testable.
  2. Order matters in Starlette/FastAPI: middleware is applied bottom-up on
     request and top-down on response. The order here is:
       [outermost]  CORSMiddleware
                    RequestIDMiddleware
                    RequestLoggingMiddleware
       [innermost]  → route handler
     CORS must be outermost so pre-flight OPTIONS requests are handled before
     any auth or logging logic runs.
  3. `RequestIDMiddleware` injects a UUID into every request. The ID is
     attached to the response as `X-Request-ID` and is available in
     `request.state.request_id` for structured logging throughout the
     request lifecycle.
  4. `RequestLoggingMiddleware` logs method, path, status code, and duration.
     It does NOT log request bodies — these may contain wallet addresses or
     API keys. Body logging is an explicit opt-in for debug sessions only.
  5. All middleware uses `structlog` for structured JSON output consistent
     with the rest of the application.

FUTURE SCALABILITY:
  - Add `RateLimitMiddleware` (per-IP sliding window) when exposing to the
    internet — distinct from the Etherscan token bucket.
  - Add `CompressionMiddleware` (GZip) when graph payloads grow large.
  - Add `TracingMiddleware` (OpenTelemetry) when distributed tracing is needed
    in the multi-agent framework.
"""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
import structlog

from backend.settings import get_settings

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Custom middleware implementations
# ─────────────────────────────────────────────────────────────────────────────


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Injects a unique request ID into every request and response.

    - Checks for an incoming `X-Request-ID` header; uses it if present
      (allows tracing across service boundaries in future multi-agent setup).
    - Generates a new UUID4 if no incoming ID is present.
    - Attaches the ID to `request.state.request_id` for downstream use.
    - Echoes the ID back in the `X-Request-ID` response header.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs every HTTP request with method, path, status code, and duration.

    Structured log fields:
        request_id   — from request.state (set by RequestIDMiddleware)
        method       — GET, POST, etc.
        path         — URL path (no query string to avoid leaking sensitive params)
        status_code  — HTTP response status
        duration_ms  — wall-clock time in milliseconds

    Health check endpoint (/api/v1/health) is logged at DEBUG level to avoid
    flooding logs in production where health checks run every few seconds.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start_time = time.perf_counter()

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        request_id = getattr(request.state, "request_id", "unknown")

        log_kwargs = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        }

        # Suppress noisy health-check logs in production
        if request.url.path.endswith("/health"):
            logger.debug("http_request", **log_kwargs)
        else:
            logger.info("http_request", **log_kwargs)

        # Attach process time to response for client-side diagnostics
        response.headers["X-Process-Time-Ms"] = str(duration_ms)
        return response


# ─────────────────────────────────────────────────────────────────────────────
# Middleware registration
# ─────────────────────────────────────────────────────────────────────────────


def register_middleware(app: FastAPI) -> None:
    """
    Register all middleware on the FastAPI application instance.

    Called once from `main.py` during application construction, before any
    routes are mounted. Middleware is applied in reverse registration order
    (last registered = outermost), so CORS is registered last to ensure it
    wraps everything.

    Args:
        app: The FastAPI application instance.
    """
    settings = get_settings()

    # ── Custom middleware (registered first = innermost) ──────────────────────
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # ── CORS (registered last = outermost) ────────────────────────────────────
    # Must wrap everything so OPTIONS pre-flight requests are handled before
    # any auth or business logic fires.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.origins,
        allow_credentials=settings.cors.allow_credentials,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "X-Request-ID",
        ],
        expose_headers=[
            "X-Request-ID",
            "X-Process-Time-Ms",
        ],
    )
