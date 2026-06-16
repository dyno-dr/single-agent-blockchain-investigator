"""
backend/tools/transaction_stats.py
─────────────────────────────────────────────────────────────────────────────
Tool: TransactionStatsTool

PURPOSE:
  Computes aggregate TransactionStats from a list of CleanTransaction objects.
  Provides a summary object that is safe to pass to the LLM (instead of
  forwarding hundreds of raw transaction dicts).

  Used by the planner_node to give the LLM a concise numerical summary of
  wallet activity without exposing the raw transaction array.

DESIGN DECISIONS:
  1. This tool is pure computation — no I/O, no network calls. It is an
     in-process aggregation over the CleanTransaction list already in state.
  2. Returns TransactionStats (frozen Pydantic model) to match the type
     expected by the forensics rules and the normalizer output.
  3. If the input list is empty, returns a zeroed-out TransactionStats
     rather than raising — callers always get a valid object.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any

import structlog

from backend.blockchain.models import CleanTransaction, TransactionStats
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)


class TransactionStatsTool(BaseTool):
    """
    Computes aggregate statistics from a list of CleanTransaction objects.

    Usage:
        tool = TransactionStatsTool()
        stats = await tool.run(transactions=clean_tx_list)
    """

    name = "transaction_stats"
    description = "Compute aggregate wallet statistics from a list of normalised transactions."

    async def run(
        self,
        *,
        transactions: list[CleanTransaction],
        **_kwargs: Any,
    ) -> TransactionStats:
        """
        Aggregate a CleanTransaction list into a TransactionStats summary.

        Args:
            transactions: List of CleanTransaction objects from the normalizer.

        Returns:
            TransactionStats with counts, value aggregates, and timeline fields.
        """
        if not transactions:
            return TransactionStats()

        incoming_count = 0
        outgoing_count = 0
        internal_count = 0
        total_received = 0.0
        total_sent = 0.0
        largest_in = 0.0
        largest_out = 0.0
        contract_interactions = 0
        error_count = 0
        counterparties: set[str] = set()
        timestamps = []

        for tx in transactions:
            direction = tx.direction.upper()
            value = tx.value_eth

            if direction == "INCOMING":
                incoming_count += 1
                total_received += value
                if value > largest_in:
                    largest_in = value
                counterparties.add(tx.from_address)
            elif direction == "OUTGOING":
                outgoing_count += 1
                total_sent += value
                if value > largest_out:
                    largest_out = value
                counterparties.add(tx.to_address)
            else:
                internal_count += 1

            if tx.tx_type == "CONTRACT_CALL":
                contract_interactions += 1

            if tx.is_error:
                error_count += 1

            if tx.timestamp:
                ts = tx.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                timestamps.append(ts)

        total_txs = len(transactions)
        avg_value = (total_received + total_sent) / total_txs if total_txs else 0.0

        first_ts = min(timestamps) if timestamps else None
        last_ts = max(timestamps) if timestamps else None

        wallet_age_days = 0.0
        if first_ts and last_ts:
            wallet_age_days = (last_ts - first_ts).total_seconds() / 86400.0

        return TransactionStats(
            total_transactions=total_txs,
            incoming_count=incoming_count,
            outgoing_count=outgoing_count,
            internal_count=internal_count,
            total_received_eth=round(total_received, 6),
            total_sent_eth=round(total_sent, 6),
            largest_incoming_eth=round(largest_in, 6),
            largest_outgoing_eth=round(largest_out, 6),
            average_tx_value_eth=round(avg_value, 6),
            unique_counterparties=len(counterparties),
            contract_interactions=contract_interactions,
            error_transactions=error_count,
            first_tx_timestamp=first_ts,
            last_tx_timestamp=last_ts,
            wallet_age_days=round(wallet_age_days, 2),
            token_transfer_count=0,
            unique_tokens=0,
        )
