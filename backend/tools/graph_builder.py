"""
backend/tools/graph_builder.py
─────────────────────────────────────────────────────────────────────────────
Tool: GraphBuilderTool

PURPOSE:
  Assembles the final transaction graph from the accumulated state data
  (graph_nodes + graph_edges produced by tracer_node, plus the root wallet
  node from profiler_node). Annotates nodes with risk flags from the
  forensics reports. Returns the graph data dict plus a renderer mode hint
  for the frontend.

DESIGN DECISIONS:
  1. This tool does NOT use NetworkX — that's reserved for Phase 4's
     centrality/path analytics. The Phase 3 graph is a simple node-link
     dict that the frontend renders. Adding NetworkX here would be premature
     optimisation.
  2. Node deduplication: the BFS tracer may add the same wallet multiple
     times (e.g. if it appears in both depth-1 and depth-2). This tool
     deduplicates by `id` field, keeping the first occurrence.
  3. `is_flagged` annotation: nodes whose wallet address appears in any
     ForensicsReport with triggered findings get `is_flagged: True`. This
     drives the red highlight in the frontend graph renderer.
  4. The `node_count` field in the response is used by the frontend to
     select between SVG / Canvas / WebGL renderers.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.constants import GraphRendererMode
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)


class GraphBuilderTool(BaseTool):
    """
    Assembles and annotates the final transaction graph from agent state.

    Usage:
        tool = GraphBuilderTool()
        result = await tool.run(
            root_wallet=address,
            graph_nodes=nodes_list,
            graph_edges=edges_list,
            forensics_reports=reports_dict,
            settings=settings,
        )
        # result: {nodes, edges, node_count, edge_count, renderer}
    """

    name = "graph_builder"
    description = (
        "Assemble, deduplicate, and annotate the transaction graph. "
        "Returns graph data with renderer hint for the frontend."
    )

    async def run(
        self,
        *,
        root_wallet: str,
        graph_nodes: list[dict[str, Any]],
        graph_edges: list[dict[str, Any]],
        forensics_reports: dict[str, Any],
        settings: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """
        Build the final graph data structure for persistence and visualization.

        Args:
            root_wallet:       Root wallet address (always node `is_root=True`).
            graph_nodes:       Raw node list from tracer + profiler.
            graph_edges:       Raw edge list from tracer.
            forensics_reports: Dict mapping wallet → ForensicsReport.
            settings:          Application settings (for renderer thresholds).

        Returns:
            Dict with nodes, edges, node_count, edge_count, renderer hint.
        """
        # Collect wallets with triggered findings for flag annotation
        flagged_wallets: set[str] = {
            addr
            for addr, rep in forensics_reports.items()
            if rep.findings
        }

        # Ensure root wallet node exists
        node_ids: set[str] = set()
        deduped_nodes: list[dict[str, Any]] = []

        # Add root node first (always present)
        root_node = {
            "id": root_wallet,
            "label": f"{root_wallet[:6]}…{root_wallet[-4:]}",
            "type": "unknown",
            "is_root": True,
            "is_flagged": root_wallet in flagged_wallets,
            "halt_reason": None,
        }
        deduped_nodes.append(root_node)
        node_ids.add(root_wallet)

        # Add tracer nodes (skip root if already added)
        for node in graph_nodes:
            nid = node.get("id", "")
            if not nid or nid in node_ids:
                continue
            annotated = dict(node)
            annotated["is_flagged"] = nid in flagged_wallets
            deduped_nodes.append(annotated)
            node_ids.add(nid)

        # Deduplicate edges by (source, target, tx_hash)
        seen_edges: set[tuple[str, str, str]] = set()
        deduped_edges: list[dict[str, Any]] = []
        for edge in graph_edges:
            key = (edge.get("source", ""), edge.get("target", ""), edge.get("tx_hash", ""))
            if key not in seen_edges:
                deduped_edges.append(edge)
                seen_edges.add(key)

        node_count = len(deduped_nodes)
        edge_count = len(deduped_edges)
        renderer = _select_renderer(node_count, settings)

        logger.info(
            "graph_builder_complete",
            root=root_wallet,
            nodes=node_count,
            edges=edge_count,
            flagged=len(flagged_wallets),
            renderer=renderer,
        )

        return {
            "nodes": deduped_nodes,
            "edges": deduped_edges,
            "node_count": node_count,
            "edge_count": edge_count,
            "renderer": renderer,
        }


def _select_renderer(node_count: int, settings: Any) -> str:
    """Select the frontend renderer based on graph size and settings thresholds."""
    canvas_threshold = settings.graph_renderer.GRAPH_RENDERER_CANVAS_THRESHOLD
    webgl_threshold = settings.graph_renderer.GRAPH_RENDERER_WEBGL_THRESHOLD
    if node_count >= webgl_threshold:
        return GraphRendererMode.WEBGL.value
    if node_count >= canvas_threshold:
        return GraphRendererMode.CANVAS.value
    return GraphRendererMode.SVG.value
