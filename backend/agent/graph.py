"""
backend/agent/graph.py
─────────────────────────────────────────────────────────────────────────────
Compiles and returns the LangGraph investigation StateGraph.

GRAPH TOPOLOGY:
  START
    → profiler        (fetch + normalise root wallet)
    → trace_scorer    (Layer-1 deterministic scoring of counterparties)
    → planner         (LLM: select trace strategy from scored candidates)
    → detector        (run all 7 forensic rules)
    → reporter        (LLM: generate report)
    → memory          (persist to DB)
    → END

DESIGN DECISIONS:
  1. profiler runs first so wallet_profiles is populated before trace_scorer
     and planner execute. Previously planner ran before profiler which caused
     it to always fall back (no profile available).
  2. trace_scorer runs between profiler and planner so the planner LLM
     receives real scored candidates for informed strategy selection.
  3. Linear graph for Phase 3. Phase 4 will add conditional edges for
     multi-hop tracing (profiler loops back until depth exhausted).
  4. The graph is compiled once at import time. Each investigation runs
     `graph.ainvoke(initial_state)`.
  5. All nodes are pure async functions that accept AgentState and return
     partial state dicts. LangGraph merges them automatically.
  6. Error handling: any unhandled exception in a node is caught by the
     graph runner in investigation.py and marks the investigation FAILED.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from backend.agent.nodes.detector_node import detector_node
from backend.agent.nodes.memory_node import memory_node
from backend.agent.nodes.planner import planner_node
from backend.agent.nodes.profiler_node import profiler_node
from backend.agent.nodes.reporter_node import reporter_node
from backend.agent.nodes.trace_scorer_node import trace_scorer_node
from backend.agent.state import AgentState


def build_graph() -> StateGraph:
    """
    Construct and compile the investigation StateGraph.

    Returns:
        Compiled LangGraph graph ready for ainvoke().
    """
    builder = StateGraph(AgentState)

    # Register nodes
    builder.add_node("profiler", profiler_node)
    builder.add_node("trace_scorer", trace_scorer_node)
    builder.add_node("planner", planner_node)
    builder.add_node("detector", detector_node)
    builder.add_node("reporter", reporter_node)
    builder.add_node("memory", memory_node)

    # Linear edges — profiler first, then scorer feeds planner with candidates
    builder.add_edge(START, "profiler")
    builder.add_edge("profiler", "trace_scorer")
    builder.add_edge("trace_scorer", "planner")
    builder.add_edge("planner", "detector")
    builder.add_edge("detector", "reporter")
    builder.add_edge("reporter", "memory")
    builder.add_edge("memory", END)

    return builder.compile()


# Compiled graph singleton — imported by the investigation pipeline
investigation_graph = build_graph()
