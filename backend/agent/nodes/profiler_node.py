"""
backend/agent/nodes/profiler_node.py
─────────────────────────────────────────────────────────────────────────────
PROFILER node: fetches balance + transactions for the root wallet and builds
its WalletProfile. This is always the first node to run after the planner.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.blockchain.etherscan_client import EtherscanClient
from backend.blockchain.models import RawEtherscanTransaction, RawTokenTransfer
from backend.blockchain.normalizer import normalize_wallet_profile
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)


async def profiler_node(state: AgentState) -> dict[str, Any]:
    """
    Fetch and normalise the root wallet's blockchain data.

    Calls Etherscan for:
      - ETH balance
      - Normal transactions (up to max_transactions)
      - Token transfers

    Builds a WalletProfile and stores it in state.wallet_profiles.

    Args:
        state: Current AgentState.

    Returns:
        Partial state update dict.
    """
    wallet = state["wallet_address"]
    settings = state["settings"]
    http_client = state["http_client"]
    rate_limiter = state["rate_limiter"]
    lookback_days = state["lookback_days"]
    max_transactions = state["max_transactions"]

    logger.info("profiler_node_start", wallet=wallet)

    client = EtherscanClient(
        settings=settings,
        http_client=http_client,
        rate_limiter=rate_limiter,
    )

    fetch_errors: list[str] = []

    # Approximate start block from lookback_days
    now = dt.datetime.now(dt.UTC)
    days_since_genesis = (now - dt.datetime(2015, 7, 30, tzinfo=dt.UTC)).days
    approx_current_block = days_since_genesis * 6500
    start_block = max(0, approx_current_block - lookback_days * 6500)

    # Fetch transactions
    try:
        raw_tx_dicts = await client.get_transactions(
            wallet=wallet,
            start_block=start_block,
            offset=min(max_transactions, 1000),
        )
        raw_txs = [RawEtherscanTransaction(**t) for t in raw_tx_dicts]
    except Exception as exc:
        logger.warning("profiler_tx_fetch_failed", wallet=wallet, error=str(exc))
        raw_txs = []
        fetch_errors.append(f"Transaction fetch failed: {exc}")

    # Fetch token transfers
    try:
        raw_token_dicts = await client.get_token_transfers(
            wallet=wallet,
            start_block=start_block,
            offset=min(max_transactions, 1000),
        )
        raw_tokens = [RawTokenTransfer(**t) for t in raw_token_dicts]
    except Exception as exc:
        logger.warning("profiler_token_fetch_failed", wallet=wallet, error=str(exc))
        raw_tokens = []
        fetch_errors.append(f"Token transfer fetch failed: {exc}")

    # Fetch balance
    try:
        balance_wei = int(await client.get_wallet_balance(wallet))
    except Exception as exc:
        logger.warning("profiler_balance_fetch_failed", wallet=wallet, error=str(exc))
        balance_wei = 0
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
        "profiler_node_complete",
        wallet=wallet,
        tx_count=profile.stats.total_transactions,
        balance_eth=round(profile.balance_eth, 4),
        errors=len(fetch_errors),
    )

    step = ReasoningStep(
        step="PROFILER",
        action=f"Fetched profile for {wallet}",
        observation=(
            f"{profile.stats.total_transactions} transactions, "
            f"balance {profile.balance_eth:.4f} ETH"
        ),
        timestamp=utc_now_iso(),
    )

    return {
        "wallet_profiles": {**state.get("wallet_profiles", {}), wallet: profile},
        "current_phase": "PROFILING",
        "errors": fetch_errors,
        "reasoning_log": [step],
    }
