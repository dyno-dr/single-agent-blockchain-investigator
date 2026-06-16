"""
backend/tests/unit/test_blockchain.py
─────────────────────────────────────────────────────────────────────────────
Unit tests for the blockchain data layer.

Coverage:
  - NullRateLimiter / EtherscanRateLimiter interface
  - EtherscanClient happy paths (mocked HTTP)
  - EtherscanClient error paths (bad address, timeout, server error)
  - normalizer module-level functions
  - Pydantic models (RawEtherscanTransaction, RawBalanceResponse, etc.)
  - Rate limiter factory

All tests mock httpx.AsyncClient — no real Etherscan calls made.
"""

from __future__ import annotations

from datetime import UTC
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

FIXTURES_DIR = (
    Path(__file__).parent.parent / "fixtures" / "mock_etherscan_responses"
)

NORMAL_WALLET = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
HIGH_RISK_WALLET = "0xfae4b5c82f32d8e55ca7c00b86ebad37fc6af4a3"
EMPTY_WALLET = "0x" + "0" * 39 + "1"


def _load_fixture(name: str) -> dict[str, Any]:
    with open(FIXTURES_DIR / f"{name}.json") as f:
        return json.load(f)


def _mock_response(data: dict[str, Any], status_code: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = data
    return r


def _make_settings() -> MagicMock:
    s = MagicMock()
    s.etherscan.base_url = "https://api.etherscan.io/api"
    s.etherscan.api_key = "test-key"
    s.etherscan.max_retries = 2
    s.etherscan.retry_backoff_base = 0.01
    s.rate_limiter.requests_per_second = 4.5
    s.rate_limiter.burst_capacity = 5
    return s


def _make_client(http: MagicMock) -> Any:
    from backend.blockchain.etherscan_client import EtherscanClient
    from backend.blockchain.rate_limiter import NullRateLimiter
    return EtherscanClient(
        settings=_make_settings(),
        http_client=http,
        rate_limiter=NullRateLimiter(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# NullRateLimiter
# ─────────────────────────────────────────────────────────────────────────────


class TestNullRateLimiter:
    async def test_context_manager_returns_self(self):
        from backend.blockchain.rate_limiter import NullRateLimiter
        limiter = NullRateLimiter()
        async with limiter as ctx:
            assert ctx is limiter

    async def test_no_side_effects_on_repeated_use(self):
        from backend.blockchain.rate_limiter import NullRateLimiter
        limiter = NullRateLimiter()
        for _ in range(5):
            async with limiter:
                pass  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# EtherscanRateLimiter factory
# ─────────────────────────────────────────────────────────────────────────────


class TestRateLimiterFactory:
    def test_create_from_settings(self):
        from backend.blockchain.rate_limiter import create_rate_limiter
        limiter = create_rate_limiter(_make_settings())
        assert limiter.requests_per_second == 4.5
        assert limiter.burst_capacity == 5

    async def test_real_limiter_context_manager(self):
        from backend.blockchain.rate_limiter import EtherscanRateLimiter
        # High rate so test doesn't actually sleep
        limiter = EtherscanRateLimiter(requests_per_second=1000.0, burst_capacity=100)
        async with limiter:
            pass  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# EtherscanClient — happy paths
# ─────────────────────────────────────────────────────────────────────────────


class TestEtherscanClientHappyPaths:
    async def test_get_wallet_balance_returns_float(self):
        fixture = _load_fixture("normal_wallet")
        http = AsyncMock()
        http.get.return_value = _mock_response(fixture["balance"])
        client = _make_client(http)

        balance = await client.get_wallet_balance(NORMAL_WALLET)
        assert isinstance(balance, float)
        assert balance == 1_500_000_000_000_000_000.0

    async def test_get_transactions_returns_list_of_dicts(self):
        fixture = _load_fixture("normal_wallet")
        http = AsyncMock()
        http.get.return_value = _mock_response(fixture["transactions"])
        client = _make_client(http)

        txs = await client.get_transactions(NORMAL_WALLET)
        assert isinstance(txs, list)
        assert len(txs) == 2
        assert txs[0]["hash"].startswith("0x")

    async def test_get_transactions_empty_wallet_returns_empty_list(self):
        http = AsyncMock()
        http.get.return_value = _mock_response({
            "status": "0",
            "message": "No transactions found",
            "result": [],
        })
        client = _make_client(http)

        txs = await client.get_transactions(EMPTY_WALLET)
        assert txs == []

    async def test_get_internal_transactions_returns_list(self):
        http = AsyncMock()
        http.get.return_value = _mock_response(
            {"status": "1", "message": "OK", "result": []}
        )
        client = _make_client(http)
        txs = await client.get_internal_transactions(NORMAL_WALLET)
        assert isinstance(txs, list)

    async def test_get_token_transfers_empty(self):
        fixture = _load_fixture("normal_wallet")
        http = AsyncMock()
        http.get.return_value = _mock_response(fixture["token_transfers"])
        client = _make_client(http)

        transfers = await client.get_token_transfers(NORMAL_WALLET)
        assert isinstance(transfers, list)

    async def test_get_contract_info_eoa_returns_false(self):
        http = AsyncMock()
        # First call: eth_getCode → "0x" (EOA, no bytecode)
        # Second call: getabi → error (unverified/non-contract)
        http.get.side_effect = [
            _mock_response({"status": "1", "message": "OK", "result": "0x"}),
            _mock_response({
                "status": "0",
                "message": "Contract source code not verified",
                "result": "Contract source code not verified",
            }),
        ]
        client = _make_client(http)
        info = await client.get_contract_info(NORMAL_WALLET)
        assert info["is_contract"] is False
        assert info["abi"] is None

    async def test_high_risk_fixture_has_five_txs(self):
        fixture = _load_fixture("high_risk_wallet")
        http = AsyncMock()
        http.get.return_value = _mock_response(fixture["transactions"])
        client = _make_client(http)
        txs = await client.get_transactions(HIGH_RISK_WALLET)
        assert len(txs) == 5


# ─────────────────────────────────────────────────────────────────────────────
# EtherscanClient — error paths
# ─────────────────────────────────────────────────────────────────────────────


class TestEtherscanClientErrorPaths:
    async def test_invalid_address_raises_etherscan_exception(self):
        from backend.exceptions import EtherscanException
        http = AsyncMock()
        http.get.return_value = _mock_response({
            "status": "0",
            "message": "Invalid address",
            "result": "Error! Invalid address format",
        })
        client = _make_client(http)
        with pytest.raises(EtherscanException) as exc_info:
            await client.get_transactions("bad_address")
        assert "Invalid" in exc_info.value.message

    async def test_no_transactions_found_returns_empty_list(self):
        http = AsyncMock()
        http.get.return_value = _mock_response({
            "status": "0",
            "message": "No transactions found",
            "result": [],
        })
        client = _make_client(http)
        txs = await client.get_transactions(NORMAL_WALLET)
        assert txs == []

    async def test_no_records_found_returns_empty_list(self):
        http = AsyncMock()
        http.get.return_value = _mock_response({
            "status": "0",
            "message": "No records found",
            "result": [],
        })
        client = _make_client(http)
        txs = await client.get_token_transfers(NORMAL_WALLET)
        assert txs == []

    async def test_http_500_raises_etherscan_exception(self):
        from backend.exceptions import EtherscanException
        http = AsyncMock()
        http.get.return_value = _mock_response({}, status_code=500)
        client = _make_client(http)
        with pytest.raises(EtherscanException):
            await client.get_transactions(NORMAL_WALLET)

    async def test_result_not_list_raises_etherscan_exception(self):
        from backend.exceptions import EtherscanException
        http = AsyncMock()
        http.get.return_value = _mock_response({
            "status": "1",
            "message": "OK",
            "result": "unexpected_string_not_list",
        })
        client = _make_client(http)
        with pytest.raises(EtherscanException):
            await client.get_transactions(NORMAL_WALLET)

    async def test_network_timeout_raises_etherscan_exception(self):
        import httpx

        from backend.exceptions import EtherscanException
        http = AsyncMock()
        http.get.side_effect = httpx.TimeoutException("timeout")
        client = _make_client(http)
        with pytest.raises(EtherscanException):
            await client.get_transactions(NORMAL_WALLET)

    async def test_network_error_raises_etherscan_exception(self):
        import httpx

        from backend.exceptions import EtherscanException
        http = AsyncMock()
        http.get.side_effect = httpx.NetworkError("connection refused")
        client = _make_client(http)
        with pytest.raises(EtherscanException):
            await client.get_transactions(NORMAL_WALLET)

    async def test_general_api_error_raises_etherscan_exception(self):
        from backend.exceptions import EtherscanException
        http = AsyncMock()
        http.get.return_value = _mock_response({
            "status": "0",
            "message": "Something went wrong",
            "result": "Error",
        })
        client = _make_client(http)
        with pytest.raises(EtherscanException):
            await client.get_transactions(NORMAL_WALLET)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────


class TestBlockchainModels:
    def test_raw_etherscan_transaction_parses(self):
        from backend.blockchain.models import RawEtherscanTransaction
        raw = {
            "blockNumber": "17000000",
            "timeStamp": "1682000000",
            "hash": "0x" + "a" * 64,
            "nonce": "10",
            "blockHash": "0x" + "b" * 64,
            "transactionIndex": "5",
            "from": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
            "to": "0xa090e606e30bd747d4e6245a1517ebe430f0057e",
            "value": "500000000000000000",
            "gas": "21000",
            "gasPrice": "20000000000",
            "isError": "0",
            "txreceipt_status": "1",
            "input": "0x",
            "contractAddress": "",
            "cumulativeGasUsed": "105000",
            "gasUsed": "21000",
            "confirmations": "1000",
        }
        tx = RawEtherscanTransaction(**raw)
        assert tx.blockNumber == "17000000"
        assert tx.value == "500000000000000000"
        assert tx.isError == "0"
        # `from` field aliased to `from_`
        assert tx.from_ == "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"

    def test_raw_balance_response_parses(self):
        from backend.blockchain.models import RawBalanceResponse
        r = RawBalanceResponse(status="1", message="OK", result="1500000000000000000")
        assert r.result == "1500000000000000000"

    def test_raw_transaction_list_coerces_string_result_to_empty_list(self):
        from backend.blockchain.models import RawTransactionListResponse
        r = RawTransactionListResponse(
            status="0",
            message="No transactions found",
            result="No transactions found",
        )
        assert r.result == []

    def test_raw_token_transfer_list_coerces_string_to_empty(self):
        from backend.blockchain.models import RawTokenTransferListResponse
        r = RawTokenTransferListResponse(
            status="0", message="No records found", result="No records found"
        )
        assert r.result == []

    def test_clean_transaction_is_frozen(self):
        from backend.blockchain.models import RawEtherscanTransaction
        from backend.blockchain.normalizer import normalize_transaction
        raw = RawEtherscanTransaction(
            blockNumber="17000000", timeStamp="1682000000",
            hash="0x" + "a" * 64, nonce="0", blockHash="0x" + "b" * 64,
            transactionIndex="0", **{"from": NORMAL_WALLET}, to=HIGH_RISK_WALLET,
            value="1000000000000000000", gas="21000", gasPrice="1000000000",
            isError="0", txreceipt_status="1", input="0x",
            contractAddress="", cumulativeGasUsed="21000",
            gasUsed="21000", confirmations="100",
        )
        tx = normalize_transaction(raw, target_address=NORMAL_WALLET)
        with pytest.raises(Exception):  # frozen=True prevents attribute assignment
            tx.hash = "changed"  # type: ignore[misc]

    def test_wallet_profile_is_frozen(self):
        from datetime import datetime, timezone

        from backend.blockchain.normalizer import normalize_wallet_profile
        profile = normalize_wallet_profile(
            address=NORMAL_WALLET,
            balance_wei=0,
            raw_transactions=[],
            raw_token_transfers=[],
            fetched_at=datetime.now(UTC),
        )
        with pytest.raises(Exception):
            profile.address = "changed"  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────────────────
# Normalizer
# ─────────────────────────────────────────────────────────────────────────────

_SAMPLE_RAW_DICT = {
    "blockNumber": "17000000",
    "timeStamp": "1682000000",
    "hash": "0x" + "a" * 64,
    "nonce": "10",
    "blockHash": "0x" + "b" * 64,
    "transactionIndex": "5",
    "from": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
    "to": "0xa090e606e30bd747d4e6245a1517ebe430f0057e",
    "value": "500000000000000000",
    "gas": "21000",
    "gasPrice": "20000000000",
    "isError": "0",
    "txreceipt_status": "1",
    "input": "0x",
    "contractAddress": "",
    "cumulativeGasUsed": "105000",
    "gasUsed": "21000",
    "confirmations": "1000",
}


def _make_raw_tx(**overrides: Any):
    from backend.blockchain.models import RawEtherscanTransaction
    data = {**_SAMPLE_RAW_DICT, **overrides}
    return RawEtherscanTransaction(**data)


class TestNormalizer:
    def test_wei_to_eth_conversion(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        assert abs(tx.value_eth - 0.5) < 1e-9

    def test_timestamp_is_utc_aware_datetime(self):
        from datetime import datetime

        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        assert isinstance(tx.timestamp, datetime)
        assert tx.timestamp.tzinfo is not None

    def test_outgoing_direction(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        assert tx.direction == "OUTGOING"

    def test_incoming_direction(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(
            _make_raw_tx(**{
                "from": "0xa090e606e30bd747d4e6245a1517ebe430f0057e",
                "to": NORMAL_WALLET,
            }),
            target_address=NORMAL_WALLET,
        )
        assert tx.direction == "INCOMING"

    def test_block_number_converted_to_int(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        assert isinstance(tx.block_number, int)
        assert tx.block_number == 17_000_000

    def test_is_error_flag_true(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(isError="1"), target_address=NORMAL_WALLET)
        assert tx.is_error is True

    def test_is_error_flag_false(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(isError="0"), target_address=NORMAL_WALLET)
        assert tx.is_error is False

    def test_gas_cost_eth_calculation(self):
        from backend.blockchain.normalizer import normalize_transaction
        # gasUsed=21000, gasPrice=20000000000 → 420000000000000 wei → 0.00042 ETH
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        expected = 21_000 * 20_000_000_000 / 1e18
        assert abs(tx.gas_cost_eth - expected) < 1e-12

    def test_from_address_lowercased(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        assert tx.from_address == tx.from_address.lower()

    def test_to_address_lowercased(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(), target_address=NORMAL_WALLET)
        assert tx.to_address == tx.to_address.lower()

    def test_known_cex_entity_tagged_on_to(self):
        """Coinbase Hot Wallet 1 (to address) should be tagged as known_cex."""
        from backend.blockchain.normalizer import normalize_transaction
        coinbase = "0xa090e606e30bd747d4e6245a1517ebe430f0057e"
        tx = normalize_transaction(
            _make_raw_tx(**{"from": NORMAL_WALLET, "to": coinbase}),
            target_address=NORMAL_WALLET,
        )
        assert tx.to_entity_label is not None
        assert tx.to_entity_type == "known_cex"

    def test_unknown_address_has_no_entity(self):
        from backend.blockchain.normalizer import normalize_transaction
        unknown = "0x" + "f" * 40
        tx = normalize_transaction(
            _make_raw_tx(**{"from": NORMAL_WALLET, "to": unknown}),
            target_address=NORMAL_WALLET,
        )
        assert tx.to_entity_label is None
        assert tx.to_entity_type is None

    def test_contract_call_tx_type(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(
            _make_raw_tx(input="0xabcd1234", functionName="transfer(address,uint256)"),
            target_address=NORMAL_WALLET,
        )
        assert tx.tx_type == "CONTRACT_CALL"

    def test_transfer_tx_type(self):
        from backend.blockchain.normalizer import normalize_transaction
        tx = normalize_transaction(_make_raw_tx(input="0x"), target_address=NORMAL_WALLET)
        assert tx.tx_type == "TRANSFER"

    def test_normalize_wallet_profile_basic(self):
        from datetime import datetime, timezone

        from backend.blockchain.models import RawEtherscanTransaction
        from backend.blockchain.normalizer import normalize_wallet_profile

        fixture = _load_fixture("normal_wallet")
        raw_txs = [RawEtherscanTransaction(**t) for t in fixture["transactions"]["result"]]

        profile = normalize_wallet_profile(
            address=NORMAL_WALLET,
            balance_wei=int(fixture["balance"]["result"]),
            raw_transactions=raw_txs,
            raw_token_transfers=[],
            fetched_at=datetime.now(UTC),
        )
        assert profile.address == NORMAL_WALLET
        assert abs(profile.balance_eth - 1.5) < 1e-9
        assert profile.stats.total_transactions == 2
        assert profile.stats.first_tx_timestamp is not None
        assert profile.stats.last_tx_timestamp is not None

    def test_empty_wallet_profile(self):
        from datetime import datetime, timezone

        from backend.blockchain.normalizer import normalize_wallet_profile

        profile = normalize_wallet_profile(
            address=EMPTY_WALLET,
            balance_wei=0,
            raw_transactions=[],
            raw_token_transfers=[],
            fetched_at=datetime.now(UTC),
        )
        assert profile.balance_eth == 0.0
        assert profile.stats.total_transactions == 0
        assert profile.stats.first_tx_timestamp is None

    def test_stats_incoming_outgoing_counts(self):
        from datetime import datetime, timezone

        from backend.blockchain.models import RawEtherscanTransaction
        from backend.blockchain.normalizer import normalize_wallet_profile

        fixture = _load_fixture("normal_wallet")
        raw_txs = [RawEtherscanTransaction(**t) for t in fixture["transactions"]["result"]]
        # tx[0]: from=NORMAL_WALLET → OUTGOING; tx[1]: to=NORMAL_WALLET → INCOMING
        profile = normalize_wallet_profile(
            address=NORMAL_WALLET,
            balance_wei=0,
            raw_transactions=raw_txs,
            raw_token_transfers=[],
            fetched_at=datetime.now(UTC),
        )
        assert profile.stats.outgoing_count == 1
        assert profile.stats.incoming_count == 1

    def test_compute_stats_empty(self):
        from backend.blockchain.normalizer import compute_stats
        stats = compute_stats([], [])
        assert stats.total_transactions == 0
        assert stats.average_tx_value_eth == 0.0
