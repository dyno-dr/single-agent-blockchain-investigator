"""
backend/agent/graph.py
─────────────────────────────────────────────────────────────────────────────
Compiles and returns the LangGraph investigation StateGraph.

GRAPH TOPOLOGY:
  START
    → planner         (LLM: select trace strategy)
    → profiler        (fetch + normalise root wallet)
    → detector        (run all 7 forensic rules)
    → reporter        (LLM: generate report)
    → memory          (persist to DB)
    → END

DESIGN DECISIONS:
  1. Linear graph for Phase 3. Phase 4 will add conditional edges for
     multi-hop tracing (profiler loops back until depth exhausted).
  2. The graph is compiled once at import time. Each investigation runs
     `graph.ainvoke(initial_state)`.
  3. All nodes are pure async functions that accept AgentState and return
     partial state dicts. LangGraph merges them automatically.
  4. Error handling: any unhandled exception in a node is caught by the
     graph runner in investigation.py and marks the investigation FAILED.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from backend.agent.state import AgentState
from backend.agent.nodes.planner import planner_node
from backend.agent.nodes.profiler_node import profiler_node
from backend.agent.nodes.detector_node import detector_node
from backend.agent.nodes.reporter_node import reporter_node
from backend.agent.nodes.memory_node import memory_node


def build_graph() -> StateGraph:
    """
    Construct and compile the investigation StateGraph.

    Returns:
        Compiled LangGraph graph ready for ainvoke().
    """
    builder = StateGraph(AgentState)

    # Register nodes
    builder.add_node("planner", planner_node)
    builder.add_node("profiler", profiler_node)
    builder.add_node("detector", detector_node)
    builder.add_node("reporter", reporter_node)
    builder.add_node("memory", memory_node)

    # Linear edges
    builder.add_edge(START, "planner")
    builder.add_edge("planner", "profiler")
    builder.add_edge("profiler", "detector")
    builder.add_edge("detector", "reporter")
    builder.add_edge("reporter", "memory")
    builder.add_edge("memory", END)

    return builder.compile()


# Compiled graph singleton — imported by the investigation pipeline
investigation_graph = build_graph()