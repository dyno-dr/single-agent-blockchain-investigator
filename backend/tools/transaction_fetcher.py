"""
backend/tools/transaction_fetcher.py
─────────────────────────────────────────────────────────────────────────────
Tool: TransactionFetcherTool

PURPOSE:
  Fetches raw normalised transactions for a single wallet during multi-hop
  tracing. Unlike WalletProfilerTool (which builds the full WalletProfile),
  this tool returns only the CleanTransaction list — the minimal data needed
  by the tracer_node to identify next-hop candidates.

  Used by tracer_node during depth > 1 tracing when the profiler has already
  handled depth-0 (root wallet).

DESIGN DECISIONS:
  1. Returns List[CleanTransaction] not WalletProfile. The tracer does not
     need stats, token transfers, or balance for hop wallets — just the
     transaction counterparty graph.
  2. Errors return an empty list with a logged warning. The tracer treats
     empty results as a dead end and skips to the next candidate.
  3. Direction filter: for FORWARD_ONLY strategy, we only need outgoing txs;
     for BACKWARD_ONLY, only incoming. This is a future optimization — Phase 3
     fetches all directions and lets the tracer filter.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import structlog

from backend.blockchain.etherscan_client import EtherscanClient
from backend.blockchain.models import CleanTransaction, RawEtherscanTransaction
from backend.blockchain.normalizer import normalize_transaction
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

_BLOCKS_PER_DAY = 6500
_ETH_GENESIS = dt.datetime(2015, 7, 30, tzinfo=dt.UTC)


class TransactionFetcherTool(BaseTool):
    """
    Fetches normalised transactions for a wallet during hop tracing.

    Returns a list of CleanTransaction objects — the minimal data needed
    by the tracer to identify and score next-hop candidates.

    Usage:
        tool = TransactionFetcherTool()
        txs = await tool.run(
            wallet=address,
            lookback_days=90,
            max_transactions=200,
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )
    """

    name = "transaction_fetcher"
    description = "Fetch normalised transactions for a wallet address during multi-hop tracing."

    async def run(
        self,
        *,
        wallet: str,
        lookback_days: int,
        max_transactions: int,
        settings: Any,
        http_client: Any,
        rate_limiter: Any,
    ) -> list[CleanTransaction]:
        """
        Fetch and normalise transactions for the given wallet.

        Args:
            wallet:           Ethereum address (lowercase).
            lookback_days:    Transaction lookback window.
            max_transactions: Max transactions to fetch.
            settings:         Application Settings instance.
            http_client:      Shared httpx.AsyncClient.
            rate_limiter:     EtherscanRateLimiter instance.

        Returns:
            List of CleanTransaction objects. Empty list on error.
        """
        logger.debug("transaction_fetcher_start", wallet=wallet)

        client = EtherscanClient(
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )

        now = dt.datetime.now(dt.UTC)
        days_since_genesis = (now - _ETH_GENESIS).days
        approx_current = days_since_genesis * _BLOCKS_PER_DAY
        start_block = max(0, approx_current - lookback_days * _BLOCKS_PER_DAY)

        try:
            raw_dicts = await client.get_transactions(
                wallet=wallet,
                start_block=start_block,
                offset=min(max_transactions, 1000),
            )
            transactions = [
                normalize_transaction(
                    RawEtherscanTransaction(**tx),
                    target_address=wallet,
                )
                for tx in raw_dicts
            ]
            logger.debug(
                "transaction_fetcher_complete",
                wallet=wallet,
                count=len(transactions),
            )
            return transactions

        except Exception as exc:
            logger.warning(
                "transaction_fetcher_failed",
                wallet=wallet,
                error=str(exc),
            )
            return []
