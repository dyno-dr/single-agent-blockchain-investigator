"""
backend/api/routers/graph.py
─────────────────────────────────────────────────────────────────────────────
GET /graph/{investigation_id} — transaction graph for visualization

PURPOSE:
  Returns the transaction graph data for a completed investigation. The graph
  is used by the frontend to render an interactive node/edge visualization.

PHASE 2 STUB:
  Returns a minimal graph with only the root wallet node. Phase 3 populates
  this with the full traced transaction graph (nodes = wallets, edges = txs).
  The route signature and response format are final.

GRAPH DATA FORMAT:
  {
    "nodes": [{"id": "<address>", "label": "<label>", "type": "<entity_type>", ...}],
    "edges": [{"source": "<from>", "target": "<to>", "tx_hash": "...", "value_eth": ...}],
    "renderer": "svg" | "canvas" | "webgl",  // hint for frontend renderer selection
    "node_count": int,
    "edge_count": int,
  }
"""

from __future__ import annotations

from typing import Annotated, Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, status
import structlog

from backend.constants import GraphRendererMode
from backend.dependencies import AuthDep, SettingsDep
from backend.persistence.database import get_db
from backend.persistence.repositories import InvestigationRepository, ReportRepository

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Graph"])

DbDep = Annotated[aiosqlite.Connection, Depends(get_db)]


# ─────────────────────────────────────────────────────────────────────────────
# GET /graph/{investigation_id}
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/graph/{investigation_id}",
    summary="Get transaction graph",
    description=(
        "Returns the transaction graph for a completed investigation. "
        "The `renderer` field hints which frontend renderer to use based on node count."
    ),
    responses={
        404: {"description": "Investigation not found."},
        425: {"description": "Investigation not yet complete."},
    },
)
async def get_graph(
    investigation_id: str,
    db: DbDep,
    settings: SettingsDep,
    _auth: AuthDep,
) -> dict[str, Any]:
    """
    Return the transaction graph for a completed investigation.

    In Phase 2 returns a stub graph with just the root wallet node.
    Phase 3 populates this with the full traced graph from the agent output.

    Args:
        investigation_id: UUID4 investigation session ID.

    Returns:
        Graph dict with nodes, edges, renderer hint, and counts.

    Raises:
        HTTPException 404: Investigation not found.
        HTTPException 425: Investigation not yet complete.
    """
    inv_repo = InvestigationRepository(db)
    report_repo = ReportRepository(db)

    inv = await inv_repo.get(investigation_id)
    if inv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    if inv["status"] in ("PENDING", "RUNNING"):
        raise HTTPException(
            status_code=425,
            detail=f"Investigation '{investigation_id}' is still {inv['status']}.",
        )

    if inv["status"] == "FAILED":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Investigation '{investigation_id}' failed and has no graph data.",
        )

    # Try to load graph_data from a persisted report (Phase 3+)
    report = await report_repo.get_by_investigation(investigation_id)
    if report is not None and report.get("graph_data"):
        graph = report["graph_data"]
        node_count = len(graph.get("nodes", []))
        edge_count = len(graph.get("edges", []))
        renderer = _select_renderer(node_count, settings)
        return {**graph, "renderer": renderer, "node_count": node_count, "edge_count": edge_count}

    # Phase 2 stub: single-node graph (root wallet only)
    wallet = inv["wallet_address"]
    stub_graph: dict[str, Any] = {
        "nodes": [
            {
                "id": wallet,
                "label": f"{wallet[:6]}…{wallet[-4:]}",
                "type": "unknown",
                "is_root": True,
                "risk_score": float(inv.get("risk_score") or 0.0),
            }
        ],
        "edges": [],
        "renderer": GraphRendererMode.SVG.value,
        "node_count": 1,
        "edge_count": 0,
    }
    return stub_graph


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _select_renderer(node_count: int, settings: Any) -> str:
    """
    Select the appropriate frontend renderer based on graph size.

    Thresholds are read from settings so they can be tuned without code changes.

    Args:
        node_count: Number of graph nodes.
        settings: Application settings (graph_renderer sub-model).

    Returns:
        Renderer mode string: "svg" | "canvas" | "webgl".
    """
    canvas_threshold = settings.graph_renderer.GRAPH_RENDERER_CANVAS_THRESHOLD
    webgl_threshold = settings.graph_renderer.GRAPH_RENDERER_WEBGL_THRESHOLD

    if node_count >= webgl_threshold:
        return GraphRendererMode.WEBGL.value
    if node_count >= canvas_threshold:
        return GraphRendererMode.CANVAS.value
    return GraphRendererMode.SVG.value
