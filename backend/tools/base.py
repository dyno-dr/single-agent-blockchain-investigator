"""
backend/tools/base.py
─────────────────────────────────────────────────────────────────────────────
Abstract base class for all agent tool wrappers.

PURPOSE:
  Every tool in the agent layer is a thin wrapper that encapsulates one
  coherent unit of work (profile a wallet, fetch transactions, score traces,
  build a graph). The base class enforces a consistent interface so nodes can
  call any tool through the same contract.

DESIGN DECISIONS:
  1. Tools are stateless dataclasses: all context is passed into `run()`.
     This makes them safe to reuse across concurrent investigations.
  2. Tools do NOT inherit from LangChain's BaseTool because this agent uses
     direct async function calls, not the LangChain tool executor. The
     LangGraph nodes call tools directly; adding LangChain overhead would
     complicate the execution model without benefit.
  3. `run()` always returns a typed result. Individual tools define their
     own return type in their implementation. The base class defines the
     async contract only.
  4. `name` and `description` are class attributes so they can be inspected
     without instantiation — useful for the session_manager's tool registry.

FUTURE SCALABILITY:
  - When adding LangChain tool_choice / structured output, subclass
    LangChainToolMixin here rather than in each tool.
  - The `name` attribute maps directly to the LangGraph tool_node registry
    when Phase 4 adds parallel tool execution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseTool(ABC):
    """
    Abstract base for all agent tool implementations.

    Every tool must define:
        name        : str — unique tool identifier used in reasoning logs
        description : str — one-line description of what the tool does

    And implement:
        run(**kwargs) → Any
    """

    name: str
    description: str

    @abstractmethod
    async def run(self, **kwargs: Any) -> Any:
        """
        Execute the tool's core logic.

        All tool inputs are keyword arguments for clarity.
        Return type is tool-specific and documented in each subclass.

        Raises:
            Exception: Tools may raise any exception; callers are responsible
                       for catching and logging tool failures.
        """
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"