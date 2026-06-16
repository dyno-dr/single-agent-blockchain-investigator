"""
backend/tools/trace_scorer.py
─────────────────────────────────────────────────────────────────────────────
Tool: TraceScorerTool

PURPOSE:
  Wraps the forensics.TraceScorer to rank candidate wallets for multi-hop
  tracing. Called by trace_scorer_node before tracer_node to determine which
  counterparty wallets should be followed and in what priority order.

INPUT CONTRACT:
  Candidates are extracted from a WalletProfile's outgoing transactions.
  Each candidate is a (wallet_address, CleanTransaction) pair.

OUTPUT CONTRACT:
  Returns the candidates list sorted by priority score descending, with each
  item annotated with a `trace_score` float in [0.0, 1.0].

DESIGN DECISIONS:
  1. The actual scoring math lives in forensics/trace_scorer.py (the
     deterministic math layer). This tool is just the agent-layer wrapper
     that bridges AgentState to the scorer's interface.
  2. The rule_triggered_wallets set is derived from state.forensics_reports —
     wallets that already have findings score higher (rule layer weight = 0.2).
  3. Candidates are capped at the configured K value based on depth before
     being returned. This is the final guard before the tracer runs.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.blockchain.models import WalletProfile
from backend.forensics.trace_scorer import TraceScorer
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

_DEPTH_K_MAP = {1: 3, 2: 3, 3: 7}  # top-K candidates per depth level


class TraceScorerTool(BaseTool):
    """
    Ranks candidate wallets for multi-hop tracing using the 3-layer scorer.

    Usage:
        tool = TraceScorerTool()
        ranked = await tool.run(
            profile=wallet_profile,
            trace_strategy=strategy,
            traced_wallets=already_traced,
            forensics_reports=reports,
            depth=2,
            settings=settings,
        )
    """

    name = "trace_scorer"
    description = (
        "Rank outgoing/incoming counterparty wallets by trace priority "
        "using value, recency, novelty, and rule-trigger layers."
    )

    def __init__(self) -> None:
        self._scorer = TraceScorer()

    async def run(
        self,
        *,
        profile: WalletProfile,
        trace_strategy: str,
        traced_wallets: set[str],
        forensics_reports: dict[str, Any],
        depth: int,
        settings: Any,
        **_kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        Score and rank counterparty wallets from a WalletProfile.

        Args:
            profile:           WalletProfile of the wallet being expanded.
            trace_strategy:    TraceStrategy enum value (FORWARD_ONLY etc).
            traced_wallets:    Set of already-traced wallet addresses.
            forensics_reports: Dict mapping wallet → ForensicsReport.
            depth:             Current trace depth (determines top-K cutoff).
            settings:          Application settings.

        Returns:
            Sorted list of candidate dicts, highest priority first.
            Each dict: {wallet, tx, trace_score, value_eth}
        """
        wallet = profile.address

        # Determine which wallets have already triggered rules
        rule_triggered: set[str] = {
            addr
            for addr, rep in forensics_reports.items()
            if rep.findings
        }

        # Build candidate list from transactions based on strategy
        candidates: list[dict[str, Any]] = []
        strategy = trace_strategy.upper()

        for tx in profile.transactions:
            direction = tx.direction.upper()

            # Filter by strategy
            if strategy == "FORWARD_ONLY" and direction != "OUTGOING":
                continue
            if strategy == "BACKWARD_ONLY" and direction != "INCOMING":
                continue

            # Identify the counterparty address
            if direction == "OUTGOING":
                counterparty = tx.to_address
            elif direction == "INCOMING":
                counterparty = tx.from_address
            else:
                continue  # skip INTERNAL

            if not counterparty or counterparty == wallet:
                continue

            candidates.append({
                "wallet": counterparty,
                "tx": tx,
                "value_eth": tx.value_eth,
            })

        if not candidates:
            logger.debug("trace_scorer_no_candidates", wallet=wallet, strategy=strategy)
            return []

        # Compute max outgoing value for normalisation
        max((c["value_eth"] for c in candidates), default=1.0) or 1.0

        # Score and rank
        ranked = self._scorer.score_and_rank(
            candidates=candidates,
            traced_wallets=traced_wallets,
            rule_triggered_wallets=rule_triggered,
            settings=settings,
        )

        # Apply top-K cap for this depth level
        k = _DEPTH_K_MAP.get(depth, 3)
        ranked = ranked[:k]

        logger.info(
            "trace_scorer_complete",
            wallet=wallet,
            strategy=strategy,
            candidates_total=len(candidates),
            candidates_selected=len(ranked),
            depth=depth,
        )
        return ranked
