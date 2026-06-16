"""
backend/logging_config.py
─────────────────────────────────────────────────────────────────────────────
Structured logging configuration using structlog.

PURPOSE:
  Configures structlog as the application-wide logging library. All modules
  obtain their logger via `structlog.get_logger(__name__)`. This module is
  the single place where the logging pipeline is assembled — processors,
  renderers, and stdlib integration.

DESIGN DECISIONS:
  1. structlog is configured once at application startup via `configure_logging()`,
     called from main.py before any other initialisation. After that, every
     `structlog.get_logger()` call returns a pre-configured, context-aware
     logger without further setup.
  2. Two render modes:
       - `json`    → `structlog.processors.JSONRenderer` — for production,
                     log aggregators (Datadog, Loki, CloudWatch), and CI.
       - `console` → `structlog.dev.ConsoleRenderer` — for local development,
                     coloured, human-readable, with pretty tracebacks.
     The mode is controlled by `LOG_FORMAT` in .env.
  3. Python's stdlib `logging` is bridged through structlog so third-party
     libraries (uvicorn, httpx, fastapi) emit structured logs in the same
     format as application code.
  4. Log level is read from settings at configure time. Changing the level
     requires an application restart — it is not hot-reloadable.
  5. Sensitive fields are never logged by design. The `mask_api_key` utility
     exists for the rare cases where key presence must be confirmed.

FUTURE SCALABILITY:
  - Add `structlog.contextvars.merge_contextvars` for per-request context
    propagation when the agent emits logs mid-investigation.
  - Add OpenTelemetry trace ID injection processor when distributed tracing
    is enabled in the multi-agent phase.
  - Add async-safe processors when the investigation volume justifies it.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from backend.settings import get_settings


def configure_logging() -> None:
    """
    Configure structlog and the stdlib logging bridge.

    Must be called once at application startup (from main.py lifespan),
    before any `structlog.get_logger()` calls in business logic execute.

    The configuration:
    - Sets the log level on the root stdlib logger (bridges third-party libs).
    - Builds the structlog processor chain based on LOG_FORMAT setting.
    - Calls `structlog.configure()` to make the pipeline global.
    """
    settings = get_settings()
    log_level_str = settings.logging.level.upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    log_format = settings.logging.format

    # ── Shared processors (applied regardless of renderer) ───────────────────
    # Note: add_logger_name requires stdlib LoggerFactory (not PrintLoggerFactory)
    # because it reads the `.name` attribute set by stdlib logging.
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    # ── Renderer-specific chain ───────────────────────────────────────────────
    if log_format == "console":
        processors: list[Any] = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]
    else:
        # JSON — production default
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        # Use stdlib LoggerFactory so add_logger_name can read logger.name
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # ── Bridge stdlib logging → structlog ────────────────────────────────────
    # uvicorn, httpx, and other libraries use stdlib logging.
    # This bridge forwards their records into the structlog pipeline so all
    # logs appear in the same format.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    # Suppress uvicorn's default access log (our middleware handles it)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(log_level)

    # Reduce httpx noise in production
    if log_format == "json":
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Optionally write to a log file in addition to stdout
    if settings.logging.file:
        file_handler = logging.FileHandler(settings.logging.file)
        file_handler.setLevel(log_level)
        logging.getLogger().addHandler(file_handler)

    # Emit a startup confirmation
    startup_logger = structlog.get_logger("logging_config")
    startup_logger.info(
        "logging_configured",
        level=log_level_str,
        format=log_format,
        log_file=settings.logging.file or None,
    )
