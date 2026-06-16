"""
backend/blockchain/normalizer.py
─────────────────────────────────────────────────────────────────────────────
Converts raw Etherscan API responses into clean, strongly-typed internal
models. This is the single point of data transformation in the blockchain
layer — no other module should parse raw Etherscan strings.

RESPONSIBILITIES:
  1. Wei → ETH conversion for all value fields
  2. Unix timestamp (str) → datetime (UTC-aware)
  3. Address lowercasing for consistent comparison
  4. Direction classification: INCOMING / OUTGOING / INTERNAL
  5. Transaction type classification: TRANSFER / CONTRACT_CALL / TOKEN_TRANSFER
  6. Entity label lookup from known_entities.json
  7. TransactionStats aggregation from the full transaction list

DESIGN DECISIONS:
  1. All methods are pure functions (no side effects, no I/O). The normalizer
     receives raw models and known_entities data and returns clean models.
     This makes it fully testable without mocking.
  2. Entity lookup is done by the normalizer (not the client) so the client
     stays focused on HTTP concerns. The known_entities dict is loaded once
     at startup and injected.
  3. Direction is determined relative to a `target_address` parameter.
     The same transaction hash appears as INCOMING to the recipient and
     OUTGOING to the sender.
  4. Gas cost is computed and stored as eth (gas_used * gas_price / 1e18)
     so forensic rules can reason about cost without recomputing.
  5. Stats are computed in a single O(n) pass over the transaction list,
     not by querying the DB again.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from typing import Any

import structlog

from backend.blockchain.models import (
    CleanTokenTransfer,
    CleanTransaction,
    RawEtherscanTransaction,
    RawTokenTransfer,
    TransactionStats,
    WalletProfile,
)

logger = structlog.get_logger(__name__)

# Path to the known_entities.json file
_ENTITIES_PATH = os.path.join(os.path.dirname(__file__), "known_entities.json")

# Module-level cache — loaded once on first use
_known_entities: dict[str, dict[str, Any]] | None = None


def _load_known_entities() -> dict[str, dict[str, Any]]:
    """
    Load and flatten known_entities.json into a single address→entity dict.

    Returns:
        Dict mapping lowercase address → {label, type, risk_note}.
    """
    global _known_entities
    if _known_entities is not None:
        return _known_entities

    try:
        with open(_ENTITIES_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        logger.warning("known_entities_not_found", path=_ENTITIES_PATH)
        _known_entities = {}
        return _known_entities

    flat: dict[str, dict[str, Any]] = {}
    for _category, entries in raw.items():
        if _category.startswith("_"):
            continue
        for address, info in entries.items():
            flat[address.lower()] = info

    _known_entities = flat
    logger.info("known_entities_loaded", count=len(flat))
    return flat


def _safe_int(value: str, default: int = 0) -> int:
    """Parse a string to int, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_float(value: str, default: float = 0.0) -> float:
    """Parse a string to float, returning default on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _wei_to_eth(wei: int) -> float:
    """Convert Wei integer to ETH float."""
    return wei / 1_000_000_000_000_000_000


def _parse_timestamp(ts: str) -> datetime:
    """Parse a Unix timestamp string to a UTC-aware datetime."""
    try:
        return datetime.fromtimestamp(int(ts), tz=UTC)
    except (ValueError, TypeError, OSError):
        return datetime.fromtimestamp(0, tz=UTC)


def _classify_direction(
    from_addr: str,
    to_addr: str,
    target_address: str,
    is_internal: bool = False,
) -> str:
    """
    Classify a transaction's direction relative to the target wallet.

    Args:
        from_addr:      Sender address (lowercase).
        to_addr:        Recipient address (lowercase).
        target_address: The wallet under investigation (lowercase).
        is_internal:    Whether this is an internal transaction.

    Returns:
        "INCOMING" | "OUTGOING" | "INTERNAL"
    """
    if is_internal:
        return "INTERNAL"
    target = target_address.lower()
    if to_addr.lower() == target:
        return "INCOMING"
    if from_addr.lower() == target:
        return "OUTGOING"
    return "INTERNAL"


def _classify_tx_type(raw: RawEtherscanTransaction) -> str:
    """
    Classify a transaction as TRANSFER, CONTRACT_CALL, or TOKEN_TRANSFER.

    Args:
        raw: Raw Etherscan transaction.

    Returns:
        Transaction type string.
    """
    if raw.contractAddress:
        return "TOKEN_TRANSFER"
    if raw.input and raw.input not in ("0x", "0x0", ""):
        return "CONTRACT_CALL"
    return "TRANSFER"


def normalize_transaction(
    raw: RawEtherscanTransaction,
    *,
    target_address: str,
    entities: dict[str, dict[str, Any]] | None = None,
) -> CleanTransaction:
    """
    Convert one raw Etherscan transaction to a CleanTransaction.

    Args:
        raw:            Raw Etherscan transaction model.
        target_address: Wallet under investigation for direction classification.
        entities:       Known-entities lookup dict (injected for testability).

    Returns:
        CleanTransaction with all fields normalised and typed.
    """
    if entities is None:
        entities = _load_known_entities()

    from_addr = raw.from_.lower()
    to_addr = raw.to.lower()

    value_wei = _safe_int(raw.value)
    gas_used = _safe_int(raw.gasUsed)
    gas_price = _safe_int(raw.gasPrice)
    gas_cost_wei = gas_used * gas_price
    function_name = raw.functionName.strip() if raw.functionName else None

    from_entity = entities.get(from_addr)
    to_entity = entities.get(to_addr)

    return CleanTransaction(
        hash=raw.hash,
        block_number=_safe_int(raw.blockNumber),
        timestamp=_parse_timestamp(raw.timeStamp),
        nonce=_safe_int(raw.nonce),
        from_address=from_addr,
        to_address=to_addr,
        contract_address=raw.contractAddress.lower() if raw.contractAddress else None,
        value_wei=value_wei,
        value_eth=_wei_to_eth(value_wei),
        gas=_safe_int(raw.gas),
        gas_price_wei=gas_price,
        gas_used=gas_used,
        gas_cost_eth=_wei_to_eth(gas_cost_wei),
        direction=_classify_direction(from_addr, to_addr, target_address),
        tx_type=_classify_tx_type(raw),
        is_error=raw.isError == "1",
        function_name=function_name if function_name else None,
        from_entity_label=from_entity["label"] if from_entity else None,
        to_entity_label=to_entity["label"] if to_entity else None,
        from_entity_type=from_entity["type"] if from_entity else None,
        to_entity_type=to_entity["type"] if to_entity else None,
    )


def normalize_token_transfer(
    raw: RawTokenTransfer,
    *,
    target_address: str,
    entities: dict[str, dict[str, Any]] | None = None,
) -> CleanTokenTransfer:
    """
    Convert one raw token transfer to a CleanTokenTransfer.

    Args:
        raw:            Raw token transfer model.
        target_address: Wallet under investigation for direction classification.
        entities:       Known-entities lookup dict.

    Returns:
        CleanTokenTransfer with all fields normalised.
    """
    if entities is None:
        entities = _load_known_entities()

    from_addr = raw.from_.lower()
    to_addr = raw.to.lower()
    decimals = _safe_int(raw.tokenDecimal, default=18)
    value_raw = _safe_int(raw.value)

    try:
        value_normalised = value_raw / (10 ** decimals)
    except (ZeroDivisionError, OverflowError):
        value_normalised = 0.0

    from_entity = entities.get(from_addr)
    to_entity = entities.get(to_addr)

    return CleanTokenTransfer(
        hash=raw.hash,
        block_number=_safe_int(raw.blockNumber),
        timestamp=_parse_timestamp(raw.timeStamp),
        from_address=from_addr,
        to_address=to_addr,
        contract_address=raw.contractAddress.lower(),
        token_name=raw.tokenName,
        token_symbol=raw.tokenSymbol,
        token_decimal=decimals,
        value_raw=value_raw,
        value_normalised=value_normalised,
        direction=_classify_direction(from_addr, to_addr, target_address),
        from_entity_label=from_entity["label"] if from_entity else None,
        to_entity_label=to_entity["label"] if to_entity else None,
    )


def compute_stats(
    transactions: list[CleanTransaction],
    token_transfers: list[CleanTokenTransfer],
) -> TransactionStats:
    """
    Compute aggregate statistics from a wallet's full transaction set.

    Performs a single O(n) pass over both lists. Called by normalize_wallet_profile.

    Args:
        transactions:    List of normalised ETH transactions.
        token_transfers: List of normalised token transfers.

    Returns:
        TransactionStats with all aggregate fields populated.
    """
    if not transactions and not token_transfers:
        return TransactionStats()

    incoming_count = outgoing_count = internal_count = 0
    total_received = total_sent = 0.0
    largest_in = largest_out = 0.0
    contract_interactions = error_count = 0
    counterparties: set[str] = set()
    timestamps: list[datetime] = []

    for tx in transactions:
        timestamps.append(tx.timestamp)

        if tx.direction == "INCOMING":
            incoming_count += 1
            total_received += tx.value_eth
            if tx.value_eth > largest_in:
                largest_in = tx.value_eth
            counterparties.add(tx.from_address)
        elif tx.direction == "OUTGOING":
            outgoing_count += 1
            total_sent += tx.value_eth
            if tx.value_eth > largest_out:
                largest_out = tx.value_eth
            counterparties.add(tx.to_address)
        else:
            internal_count += 1

        if tx.tx_type == "CONTRACT_CALL":
            contract_interactions += 1
        if tx.is_error:
            error_count += 1

    total_txs = len(transactions)
    total_value = total_received + total_sent
    avg_value = total_value / total_txs if total_txs > 0 else 0.0

    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None

    wallet_age_days = 0.0
    if first_ts and last_ts:
        wallet_age_days = (last_ts - first_ts).total_seconds() / 86400

    # Token transfer stats
    unique_tokens: set[str] = set()
    for tt in token_transfers:
        unique_tokens.add(tt.contract_address)

    return TransactionStats(
        total_transactions=total_txs,
        incoming_count=incoming_count,
        outgoing_count=outgoing_count,
        internal_count=internal_count,
        total_received_eth=round(total_received, 8),
        total_sent_eth=round(total_sent, 8),
        largest_incoming_eth=round(largest_in, 8),
        largest_outgoing_eth=round(largest_out, 8),
        average_tx_value_eth=round(avg_value, 8),
        unique_counterparties=len(counterparties),
        contract_interactions=contract_interactions,
        error_transactions=error_count,
        first_tx_timestamp=first_ts,
        last_tx_timestamp=last_ts,
        wallet_age_days=round(wallet_age_days, 2),
        token_transfer_count=len(token_transfers),
        unique_tokens=len(unique_tokens),
    )


def normalize_wallet_profile(
    *,
    address: str,
    balance_wei: int,
    raw_transactions: list[RawEtherscanTransaction],
    raw_token_transfers: list[RawTokenTransfer],
    fetched_at: datetime,
    fetch_errors: list[str] | None = None,
    entities: dict[str, dict[str, Any]] | None = None,
) -> WalletProfile:
    """
    Build a complete WalletProfile from raw Etherscan data.

    This is the main entry point called by EtherscanClient after
    all API calls complete.

    Args:
        address:              Target wallet address.
        balance_wei:          Current balance in Wei.
        raw_transactions:     Raw normal transactions from Etherscan.
        raw_token_transfers:  Raw ERC-20 transfers from Etherscan.
        fetched_at:           Timestamp when data was fetched.
        fetch_errors:         Any non-fatal errors during fetch.
        entities:             Known-entities dict (injected for testing).

    Returns:
        Fully populated WalletProfile.
    """
    if entities is None:
        entities = _load_known_entities()

    target = address.lower()

    clean_txs = [
        normalize_transaction(raw, target_address=target, entities=entities)
        for raw in raw_transactions
    ]

    clean_transfers = [
        normalize_token_transfer(raw, target_address=target, entities=entities)
        for raw in raw_token_transfers
    ]

    stats = compute_stats(clean_txs, clean_transfers)

    return WalletProfile(
        address=target,
        chain="ETHEREUM",
        fetched_at=fetched_at,
        balance_wei=balance_wei,
        balance_eth=_wei_to_eth(balance_wei),
        transactions=clean_txs,
        token_transfers=clean_transfers,
        stats=stats,
        fetch_errors=fetch_errors or [],
    )
