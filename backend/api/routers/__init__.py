"""backend/api/routers — Router package."""

from backend.api.routers.graph import router as graph_router
from backend.api.routers.health import router as health_router
from backend.api.routers.history import router as history_router
from backend.api.routers.investigation import router as investigation_router
from backend.api.routers.report import router as report_router

__all__ = [
    "graph_router",
    "health_router",
    "history_router",
    "investigation_router",
    "report_router",
]
