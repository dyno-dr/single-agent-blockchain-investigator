"""
backend/blockchain/models.py
─────────────────────────────────────────────────────────────────────────────
Pydantic models for the blockchain data layer.

TWO MODEL FAMILIES:
  1. Raw*   — direct mapping of Etherscan JSON responses. Every field is
              Optional[str] because Etherscan returns everything as strings
              and occasionally omits fields.
  2. Clean* — normalised internal models produced by normalizer.py.
              Strong types, validated fields, Wei→ETH converted.

DESIGN DECISIONS:
  1. Raw models use str for all numeric fields (Etherscan returns "12345"
     not 12345). Conversion happens in normalizer.py, not here.
  2. Clean models use Python-native types (int, float, datetime) so
     downstream code never needs to coerce types.
  3. CleanTransaction includes `entity_label` populated by known_entities.json
     lookup in the normalizer. None means unknown wallet.
  4. WalletProfile is the top-level container returned by the Etherscan
     client after fetching + normalizing all data for one wallet.
  5. All models are frozen=True (immutable) to prevent accidental mutation
     in agent nodes that pass them through the state graph.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# Raw Etherscan response models
# ─────────────────────────────────────────────────────────────────────────────


class RawEtherscanTransaction(BaseModel):
    """
    One item from the Etherscan txlist / txlistinternal response array.
    All fields are strings as returned by the API.
    """

    model_config = {"frozen": True, "extra": "ignore"}

    blockNumber: str = ""
    timeStamp: str = ""
    hash: str = ""
    nonce: str = ""
    blockHash: str = ""
    transactionIndex: str = ""
    from_: str = Field("", alias="from")
    to: str = ""
    value: str = "0"
    gas: str = "0"
    gasPrice: str = "0"
    isError: str = "0"
    txreceipt_status: str = ""
    input: str = ""
    contractAddress: str = ""
    cumulativeGasUsed: str = "0"
    gasUsed: str = "0"
    confirmations: str = "0"
    methodId: str = ""
    functionName: str = ""


class RawTokenTransfer(BaseModel):
    """
    One item from the Etherscan tokentx response array (ERC-20 transfers).
    """

    model_config = {"frozen": True, "extra": "ignore"}

    blockNumber: str = ""
    timeStamp: str = ""
    hash: str = ""
    from_: str = Field("", alias="from")
    to: str = ""
    value: str = "0"
    contractAddress: str = ""
    tokenName: str = ""
    tokenSymbol: str = ""
    tokenDecimal: str = "18"
    gas: str = "0"
    gasPrice: str = "0"
    gasUsed: str = "0"


class RawBalanceResponse(BaseModel):
    """Response from Etherscan balance endpoint."""

    model_config = {"frozen": True, "extra": "ignore"}

    status: str = "1"
    message: str = "OK"
    result: str = "0"


class RawTransactionListResponse(BaseModel):
    """Wrapper around the Etherscan txlist/txlistinternal response."""

    model_config = {"frozen": True, "extra": "ignore"}

    status: str = "1"
    message: str = "OK"
    result: list[RawEtherscanTransaction] | str = Field(default_factory=list)

    @field_validator("result", mode="before")
    @classmethod
    def coerce_empty_result(cls, v: Any) -> Any:
        # Etherscan returns result="No transactions found" (a string) when empty
        if isinstance(v, str):
            return []
        return v


class RawTokenTransferListResponse(BaseModel):
    """Wrapper around the Etherscan tokentx response."""

    model_config = {"frozen": True, "extra": "ignore"}

    status: str = "1"
    message: str = "OK"
    result: list[RawTokenTransfer] | str = Field(default_factory=list)

    @field_validator("result", mode="before")
    @classmethod
    def coerce_empty_result(cls, v: Any) -> Any:
        if isinstance(v, str):
            return []
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Clean internal models (produced by normalizer.py)
# ─────────────────────────────────────────────────────────────────────────────


class CleanTransaction(BaseModel):
    """
    Normalised representation of a single Ethereum transaction.

    Produced by normalizer.py from a RawEtherscanTransaction.
    All fields are strongly typed; no string-encoded numbers.
    """

    model_config = {"frozen": True}

    # Identity
    hash: str
    block_number: int
    timestamp: datetime
    nonce: int = 0

    # Parties
    from_address: str
    to_address: str
    contract_address: str | None = None

    # Value
    value_wei: int = 0
    value_eth: float = 0.0
    gas: int = 0
    gas_price_wei: int = 0
    gas_used: int = 0
    gas_cost_eth: float = 0.0

    # Classification
    direction: str = "UNKNOWN"        # INCOMING | OUTGOING | INTERNAL
    tx_type: str = "TRANSFER"         # TRANSFER | CONTRACT_CALL | TOKEN_TRANSFER
    is_error: bool = False
    function_name: str | None = None

    # Enrichment (from known_entities.json)
    from_entity_label: str | None = None
    to_entity_label: str | None = None
    from_entity_type: str | None = None
    to_entity_type: str | None = None


class CleanTokenTransfer(BaseModel):
    """
    Normalised ERC-20 token transfer.

    Produced by normalizer.py from a RawTokenTransfer.
    """

    model_config = {"frozen": True}

    hash: str
    block_number: int
    timestamp: datetime

    from_address: str
    to_address: str
    contract_address: str

    token_name: str = ""
    token_symbol: str = ""
    token_decimal: int = 18
    value_raw: int = 0
    value_normalised: float = 0.0

    direction: str = "UNKNOWN"
    from_entity_label: str | None = None
    to_entity_label: str | None = None


class TransactionStats(BaseModel):
    """
    Aggregate statistics computed from a wallet's transaction list.

    Used by forensic rules and the profiler node as a quick summary
    without needing to iterate all transactions again.
    """

    model_config = {"frozen": True}

    total_transactions: int = 0
    incoming_count: int = 0
    outgoing_count: int = 0
    internal_count: int = 0

    total_received_eth: float = 0.0
    total_sent_eth: float = 0.0
    largest_incoming_eth: float = 0.0
    largest_outgoing_eth: float = 0.0
    average_tx_value_eth: float = 0.0

    unique_counterparties: int = 0
    contract_interactions: int = 0
    error_transactions: int = 0

    first_tx_timestamp: datetime | None = None
    last_tx_timestamp: datetime | None = None
    wallet_age_days: float = 0.0

    # Token activity
    token_transfer_count: int = 0
    unique_tokens: int = 0


class WalletProfile(BaseModel):
    """
    Complete normalised data for one Ethereum wallet.

    Top-level container returned by EtherscanClient after fetching
    and normalising all data. Passed into the agent state graph.
    """

    model_config = {"frozen": True}

    # Identity
    address: str
    chain: str = "ETHEREUM"
    fetched_at: datetime

    # Balance
    balance_wei: int = 0
    balance_eth: float = 0.0

    # Transaction data
    transactions: list[CleanTransaction] = Field(default_factory=list)
    token_transfers: list[CleanTokenTransfer] = Field(default_factory=list)

    # Computed stats (populated by normalizer)
    stats: TransactionStats = Field(default_factory=TransactionStats)

    # Errors encountered during fetch (non-fatal)
    fetch_errors: list[str] = Field(default_factory=list)