"""
backend/tools/wallet_profiler.py
─────────────────────────────────────────────────────────────────────────────
Tool: WalletProfilerTool

PURPOSE:
  Fetches and normalises the complete on-chain profile of one Ethereum wallet.
  Wraps the Etherscan client + normalizer pipeline so agent nodes call a single
  high-level method instead of manually orchestrating three API calls.

WHAT IT DOES:
  1. Calls Etherscan `txlist`    → raw normal transactions
  2. Calls Etherscan `tokentx`   → raw ERC-20 token transfers
  3. Calls Etherscan `balance`   → ETH balance in Wei
  4. Normalises all raw data via `normalize_wallet_profile()`
  5. Returns a fully populated `WalletProfile` with computed `TransactionStats`

DESIGN DECISIONS:
  1. The tool does not cache results. The agent's state dict (`wallet_profiles`)
     serves as the per-investigation cache. Calling this tool twice for the
     same wallet in one investigation is a node logic error, not a tool concern.
  2. Partial failures (e.g. token fetch fails but tx fetch succeeds) are
     handled gracefully: errors are stored in `profile.fetch_errors` and the
     profile is returned with whatever data was successfully retrieved.
  3. Block number approximation uses 6500 blocks/day, consistent with the
     rest of the pipeline. This is conservative — actual varies ~5000-7500.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import structlog

from backend.blockchain.etherscan_client import EtherscanClient
from backend.blockchain.models import (
    RawEtherscanTransaction,
    RawTokenTransfer,
    WalletProfile,
)
from backend.blockchain.normalizer import normalize_wallet_profile
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

_BLOCKS_PER_DAY = 6500
_ETH_GENESIS = dt.datetime(2015, 7, 30, tzinfo=dt.UTC)


class WalletProfilerTool(BaseTool):
    """
    Fetches and normalises a complete WalletProfile from Etherscan.

    Usage:
        tool = WalletProfilerTool()
        profile = await tool.run(
            wallet=address,
            lookback_days=90,
            max_transactions=500,
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )
    """

    name = "wallet_profiler"
    description = "Fetch and normalise a complete on-chain profile for one Ethereum wallet."

    async def run(
        self,
        *,
        wallet: str,
        lookback_days: int,
        max_transactions: int,
        settings: Any,
        http_client: Any,
        rate_limiter: Any,
    ) -> WalletProfile:
        """
        Build a WalletProfile for the given wallet address.

        Args:
            wallet:           Ethereum address to profile (lowercase).
            lookback_days:    How far back to fetch transactions.
            max_transactions: Max transactions to fetch (capped at 1000 by Etherscan).
            settings:         Application Settings instance.
            http_client:      Shared httpx.AsyncClient.
            rate_limiter:     EtherscanRateLimiter instance.

        Returns:
            WalletProfile with normalised transactions, token transfers, and stats.
            Partial data is returned if individual API calls fail; check
            `profile.fetch_errors` for any non-fatal errors.
        """
        logger.info("wallet_profiler_start", wallet=wallet)

        client = EtherscanClient(
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )

        now = dt.datetime.now(dt.UTC)
        start_block = _approx_start_block(lookback_days, now)
        fetch_limit = min(max_transactions, 1000)
        fetch_errors: list[str] = []

        # ── Normal transactions ───────────────────────────────────────────────
        raw_txs: list[RawEtherscanTransaction] = []
        try:
            raw_tx_dicts = await client.get_transactions(
                wallet=wallet,
                start_block=start_block,
                offset=fetch_limit,
            )
            raw_txs = [RawEtherscanTransaction(**t) for t in raw_tx_dicts]
        except Exception as exc:
            logger.warning("wallet_profiler_tx_failed", wallet=wallet, error=str(exc))
            fetch_errors.append(f"Transaction fetch failed: {exc}")

        # ── Token transfers ───────────────────────────────────────────────────
        raw_tokens: list[RawTokenTransfer] = []
        try:
            raw_token_dicts = await client.get_token_transfers(
                wallet=wallet,
                start_block=start_block,
                offset=fetch_limit,
            )
            raw_tokens = [RawTokenTransfer(**t) for t in raw_token_dicts]
        except Exception as exc:
            logger.warning("wallet_profiler_token_failed", wallet=wallet, error=str(exc))
            fetch_errors.append(f"Token transfer fetch failed: {exc}")

        # ── ETH balance ───────────────────────────────────────────────────────
        balance_wei = 0
        try:
            balance_wei = int(await client.get_wallet_balance(wallet))
        except Exception as exc:
            logger.warning("wallet_profiler_balance_failed", wallet=wallet, error=str(exc))
            fetch_errors.append(f"Balance fetch failed: {exc}")

        profile = normalize_wallet_profile(
            address=wallet,
            balance_wei=balance_wei,
            raw_transactions=raw_txs,
            raw_token_transfers=raw_tokens,
            fetched_at=now,
            fetch_errors=fetch_errors,
        )

        logger.info(
            "wallet_profiler_complete",
            wallet=wallet,
            tx_count=profile.stats.total_transactions,
            balance_eth=round(profile.balance_eth, 4),
            errors=len(fetch_errors),
        )
        return profile


def _approx_start_block(lookback_days: int, now: dt.datetime) -> int:
    """Approximate the Ethereum block number `lookback_days` ago."""
    days_since_genesis = (now - _ETH_GENESIS).days
    approx_current = days_since_genesis * _BLOCKS_PER_DAY
    return max(0, approx_current - lookback_days * _BLOCKS_PER_DAY)
