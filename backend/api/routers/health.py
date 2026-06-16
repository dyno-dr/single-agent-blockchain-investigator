"""
backend/api/routers/health.py
─────────────────────────────────────────────────────────────────────────────
Health check and version endpoints.

PURPOSE:
  Provides operational visibility for the running application. The /health
  endpoint is the primary target for load balancers, container orchestrators
  (Docker healthcheck, Kubernetes liveness/readiness probes), and uptime
  monitors. The /version endpoint provides a quick way to confirm which build
  is deployed without needing to inspect container labels.

DESIGN DECISIONS:
  1. Health endpoints are NOT protected by API key authentication. Monitoring
     infrastructure must be able to check health without credentials.
  2. The health response is graduated: `ok` means all systems nominal,
     `degraded` means the app is running but a dependency is unreachable,
     `down` is reserved for fatal states (returned with HTTP 503).
  3. Checks performed (Phase 1 + persistence layer):
       - Application is running (always true if this endpoint responds)
       - Settings are loaded and readable
       - Data directory exists and is writable (skipped for :memory:)
       - Database connection is alive (via a lightweight SELECT 1)
     When the blockchain layer is added, Etherscan reachability will be
     checked here.
  4. Response time is kept minimal. No blocking I/O beyond the DB ping.
     The DB ping is a single `SELECT 1` with near-zero cost.
  5. The /version endpoint is intentionally separate from /health so
     monitoring tools can poll /health at high frequency without receiving
     the larger version payload.

BUG FIX (data_dir):
  The original health check computed:
      data_dir = os.path.dirname(settings.database_url)
  For `:memory:`, `os.path.dirname(":memory:")` returns `""`.
  `os.path.exists("")` raises no error but `os.makedirs("")` does.
  Fixed by short-circuiting the data-directory check when the DB URL is
  `:memory:` (in-memory databases have no directory).

FUTURE SCALABILITY:
  - Add `etherscan_reachable: bool` when blockchain layer ships.
  - Add `rate_limit_remaining: float` when rate limiter is wired.
  - Add `active_investigations: int` when session manager ships.
  All additions are non-breaking (new fields in the response dict).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from backend.constants import AGENT_VERSION, HEALTH_DEGRADED, HEALTH_DOWN, HEALTH_OK
from backend.dependencies import SettingsDep
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Operations"])

# Module-level startup timestamp — set when the router module is first loaded,
# which happens during application startup.
_startup_time: datetime = datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Health endpoint
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/health",
    summary="Application health check",
    description=(
        "Returns the operational status of the application and its dependencies. "
        "Used by load balancers and container orchestrators. "
        "Returns HTTP 200 for `ok` and `degraded`; HTTP 503 for `down`."
    ),
    response_description="Health status object",
)
async def health_check(settings: SettingsDep) -> JSONResponse:
    """
    Perform a lightweight health check and return the application status.

    Checks performed:
    - Application is running (implicit — response received)
    - Settings loaded correctly
    - Data directory exists and is writable (skipped for :memory:)
    - Database connection is alive

    Returns:
        JSONResponse with status 200 (ok/degraded) or 503 (down).
    """
    checks: dict[str, Any] = {}
    issues: list[str] = []

    # ── Check: Settings are accessible ───────────────────────────────────────
    try:
        _ = settings.app.version
        checks["settings"] = True
    except Exception as exc:
        checks["settings"] = False
        issues.append(f"Settings error: {exc}")

    # ── Check: Data directory exists and is writable ──────────────────────────
    # BUG FIX: os.path.dirname(":memory:") returns "" which causes os.makedirs
    # to raise FileNotFoundError. Skip the directory check for in-memory DBs.
    db_url = settings.database_url
    if db_url == ":memory:":
        # In-memory database: no directory to check; treat as writable.
        checks["data_directory"] = True
    else:
        try:
            data_dir = os.path.dirname(db_url)
            if data_dir:
                if not os.path.exists(data_dir):
                    os.makedirs(data_dir, exist_ok=True)
                checks["data_directory"] = os.access(data_dir, os.W_OK)
                if not checks["data_directory"]:
                    issues.append(f"Data directory not writable: {data_dir}")
            else:
                # Relative path with no directory component — treat as current dir
                checks["data_directory"] = os.access(".", os.W_OK)
        except Exception as exc:
            checks["data_directory"] = False
            issues.append(f"Data directory error: {exc}")

    # ── Check: Database connection is alive ───────────────────────────────────
    try:
        from backend.persistence.database import get_db_conn
        conn = get_db_conn()
        async with conn.execute("SELECT 1") as cursor:
            await cursor.fetchone()
        checks["db_connected"] = True
    except RuntimeError:
        # DB not initialised yet (e.g., health check called before lifespan)
        checks["db_connected"] = False
        issues.append("Database connection not initialised")
    except Exception as exc:
        checks["db_connected"] = False
        issues.append(f"Database error: {exc}")
    # ── Determine overall status ──────────────────────────────────────────────
    if all(checks.values()):
        overall_status = HEALTH_OK
        http_status = status.HTTP_200_OK
    elif any(checks.values()):
        overall_status = HEALTH_DEGRADED
        http_status = status.HTTP_200_OK
        logger.warning("health_check_degraded", issues=issues, checks=checks)
    else:
        overall_status = HEALTH_DOWN
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.error("health_check_down", issues=issues, checks=checks)

    uptime_seconds = (
        datetime.now(timezone.utc) - _startup_time
    ).total_seconds()

    payload: dict[str, Any] = {
        "status": overall_status,
        "version": settings.app.version,
        "environment": settings.app.env,
        "timestamp": utc_now_iso(),
        "uptime_seconds": round(uptime_seconds, 1),
        "checks": checks,
        # db_connected is now in checks; keep top-level alias for backwards compat
        "db_connected": checks.get("db_connected"),
        # Placeholders — filled in by later phases
        "etherscan_reachable": None,
        "rate_limit_remaining": None,
        "active_investigations": None,
    }

    if issues:
        payload["issues"] = issues

    return JSONResponse(content=payload, status_code=http_status)


# ─────────────────────────────────────────────────────────────────────────────
# Version endpoint
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/version",
    summary="Application version information",
    description=(
        "Returns version, build metadata, and runtime information. "
        "Useful for confirming which build is deployed."
    ),
)
async def version(settings: SettingsDep) -> dict[str, Any]:
    """
    Return application version and runtime metadata.

    This endpoint is intentionally lightweight — no dependency checks.
    For operational status use /health.
    """
    return {
        "app_name": settings.app.name,
        "version": settings.app.version,
        "agent_version": AGENT_VERSION,
        "environment": settings.app.env,
        "debug": settings.app.debug,
        "python_version": sys.version.split()[0],
        "api_prefix": settings.api.prefix,
        "timestamp": utc_now_iso(),
    }