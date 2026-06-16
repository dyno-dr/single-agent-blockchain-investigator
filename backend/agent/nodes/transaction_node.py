"""
backend/agent/nodes/transaction_node.py
─────────────────────────────────────────────────────────────────────────────
TRANSACTION node: fetches and normalises transactions for one or more wallets
that have been queued for tracing at the current depth level.

PURPOSE:
  The profiler_node handles the root wallet. For every subsequent hop wallet
  queued in state.wallets_to_trace, transaction_node fetches their transaction
  history, normalises it into WalletProfiles, and stores them in
  state.wallet_profiles keyed by address.

  The tracer_node then reads these profiles to decide which counterparties
  to queue for the next depth level.

DESIGN:
  - Processes wallets_to_trace that are NOT yet in wallet_profiles (idempotent).
  - Respects the max_transactions budget per wallet.
  - Handles per-wallet failures gracefully (logs warning, stores empty profile).
"""

from __future__ import annotations

import datetime as dt
from datetime import timezone
from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.blockchain.etherscan_client import EtherscanClient
from backend.blockchain.models import RawEtherscanTransaction, RawTokenTransfer
from backend.blockchain.normalizer import normalize_wallet_profile
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)


async def transaction_node(state: AgentState) -> dict[str, Any]:
    """
    Fetch and normalise transactions for all queued hop wallets.

    Reads:  state.wallets_to_trace (list of addresses to process)
    Writes: state.wallet_profiles  (adds new WalletProfile per wallet)

    Args:
        state: Current AgentState.

    Returns:
        Partial state update dict with updated wallet_profiles.
    """
    settings = state["settings"]
    http_client = state["http_client"]
    rate_limiter = state["rate_limiter"]
    lookback_days = state["lookback_days"]
    max_transactions = state["max_transactions"]

    wallets_to_trace = state.get("wallets_to_trace", [])
    existing_profiles = dict(state.get("wallet_profiles", {}))

    # Only process wallets we haven't profiled yet
    pending = [w for w in wallets_to_trace if w not in existing_profiles]

    if not pending:
        logger.debug("transaction_node_nothing_to_fetch")
        return {
            "current_phase": "TX_FETCH",
            "wallet_profiles": existing_profiles,
        }

    client = EtherscanClient(
        settings=settings,
        http_client=http_client,
        rate_limiter=rate_limiter,
    )

    now = dt.datetime.now(timezone.utc)
    days_since_genesis = (now - dt.datetime(2015, 7, 30, tzinfo=timezone.utc)).days
    approx_current_block = days_since_genesis * 6500
    start_block = max(0, approx_current_block - lookback_days * 6500)
    fetch_errors: list[str] = []

    for wallet in pending:
        logger.info("transaction_node_fetching", wallet=wallet)

        try:
            raw_tx_dicts = await client.get_transactions(
                wallet=wallet,
                start_block=start_block,
                offset=min(max_transactions, 1000),
            )
            raw_txs = [RawEtherscanTransaction(**t) for t in raw_tx_dicts]
        except Exception as exc:
            logger.warning("transaction_node_tx_failed", wallet=wallet, error=str(exc))
            raw_txs = []
            fetch_errors.append(f"{wallet}: tx fetch failed — {exc}")

        try:
            raw_token_dicts = await client.get_token_transfers(
                wallet=wallet,
                start_block=start_block,
                offset=min(max_transactions, 1000),
            )
            raw_tokens = [RawTokenTransfer(**t) for t in raw_token_dicts]
        except Exception as exc:
            logger.warning("transaction_node_token_failed", wallet=wallet, error=str(exc))
            raw_tokens = []

        try:
            balance_wei = int(await client.get_wallet_balance(wallet))
        except Exception as exc:
            logger.warning("transaction_node_balance_failed", wallet=wallet, error=str(exc))
            balance_wei = 0

        profile = normalize_wallet_profile(
            address=wallet,
            balance_wei=balance_wei,
            raw_transactions=raw_txs,
            raw_token_transfers=raw_tokens,
            fetched_at=now,
            fetch_errors=[],
        )
        existing_profiles[wallet] = profile

        logger.info(
            "transaction_node_profiled",
            wallet=wallet,
            tx_count=profile.stats.total_transactions,
        )

    step = ReasoningStep(
        step="TX_FETCH",
        action=f"Fetched profiles for {len(pending)} hop wallet(s)",
        observation=f"Errors: {len(fetch_errors)}",
        timestamp=utc_now_iso(),
    )

    return {
        "current_phase": "TX_FETCH",
        "wallet_profiles": existing_profiles,
        "errors": fetch_errors,
        "reasoning_log": [step],
    }