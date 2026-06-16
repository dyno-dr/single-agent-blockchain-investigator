"""
backend/blockchain/etherscan_client.py
─────────────────────────────────────────────────────────────────────────────
Async HTTP client for the Etherscan v2 API.

PURPOSE:
  Provides a typed, retry-capable, rate-limited interface to Etherscan.
  All outbound Etherscan calls originate here. Nothing else in the codebase
  constructs Etherscan URLs or interprets raw API responses.

DESIGN DECISIONS:
  1. Every method acquires a rate-limiter token before issuing the request,
     ensuring the free-tier 5 req/s limit is never exceeded.
  2. Retries are handled by `tenacity` with exponential backoff and jitter.
     Retryable errors: network errors, 429 Too Many Requests, 5xx responses.
     Non-retryable errors: 400 Bad Request, invalid address, auth errors.
  3. All Etherscan error responses (HTTP 200 with status="0") are mapped to
     `EtherscanException` with the appropriate `ErrorCode`. Callers never
     see raw API status strings.
  4. The client accepts `httpx.AsyncClient` and the rate limiter via
     constructor injection so they can be swapped in tests without touching
     the module-level singleton.
  5. Pagination: Etherscan returns at most 10,000 records per call. Methods
     that can return large result sets accept `start_block`/`end_block` to
     allow callers to page by block range if needed.

ETHERSCAN ENDPOINTS USED:
  - module=account&action=txlist            → normal transactions
  - module=account&action=txlistinternal    → internal transactions
  - module=account&action=tokentx           → ERC-20 token transfers
  - module=account&action=balance           → ETH balance
  - module=contract&action=getabi          → contract ABI (existence check)
  - module=account&action=getcode          → is address a contract?

FUTURE SCALABILITY:
  - Add `get_nft_transfers()` when ERC-721/1155 support is needed.
  - Add testnet support by parameterising base_url (already in settings).
  - Add response caching layer (Redis) between this client and callers.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from backend.constants import ErrorCode
from backend.exceptions import EtherscanException
from backend.settings import Settings

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Etherscan API status codes
# ─────────────────────────────────────────────────────────────────────────────

_STATUS_OK = "1"
_STATUS_ERROR = "0"
_MSG_NO_TRANSACTIONS = "No transactions found"
_MSG_NO_RECORDS = "No records found"


# ─────────────────────────────────────────────────────────────────────────────
# Retryable transport errors
# ─────────────────────────────────────────────────────────────────────────────


class _RetryableError(Exception):
    """Internal sentinel raised to trigger tenacity retry logic."""


# ─────────────────────────────────────────────────────────────────────────────
# Etherscan client
# ─────────────────────────────────────────────────────────────────────────────


class EtherscanClient:
    """
    Async HTTP client for the Etherscan API.

    Args:
        settings: Application settings (etherscan sub-model).
        http_client: Shared `httpx.AsyncClient` from dependency injection.
        rate_limiter: Rate limiter instance (EtherscanRateLimiter or
            NullRateLimiter). Must support `async with rate_limiter`.
    """

    def __init__(
        self,
        settings: Settings,
        http_client: httpx.AsyncClient,
        rate_limiter: Any,
    ) -> None:
        self._base_url = settings.etherscan.base_url
        self._api_key = settings.etherscan.api_key
        self._max_retries = settings.etherscan.max_retries
        self._backoff_base = settings.etherscan.retry_backoff_base
        self._http = http_client
        self._limiter = rate_limiter

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    async def get_wallet_balance(self, wallet: str) -> float:
        """
        Fetch the current ETH balance of a wallet in Wei.

        Args:
            wallet: Ethereum address (any case; validated by caller).

        Returns:
            Balance in Wei as a float. Convert to ETH with `wei_to_eth()`.

        Raises:
            EtherscanException: On API error or unreachable service.
        """
        params = {
            "module": "account",
            "action": "balance",
            "address": wallet,
            "tag": "latest",
        }
        data = await self._request(params, context={"wallet": wallet, "method": "get_wallet_balance"})
        try:
            return float(data["result"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EtherscanException(
                error_code=ErrorCode.ETHERSCAN_UNREACHABLE,
                message="Unexpected balance response format from Etherscan.",
                context={"wallet": wallet, "raw": str(data)},
                cause=exc,
            ) from exc

    async def get_transactions(
        self,
        wallet: str,
        start_block: int = 0,
        end_block: int = 99_999_999,
        page: int = 1,
        offset: int = 1000,
        sort: str = "asc",
    ) -> list[dict[str, Any]]:
        """
        Fetch normal (external) ETH transactions for a wallet.

        Args:
            wallet: Ethereum address.
            start_block: First block to include (default 0 = genesis).
            end_block: Last block to include (default covers far future).
            page: Page number for Etherscan's built-in pagination.
            offset: Number of records per page (max 10,000).
            sort: "asc" (oldest first) or "desc" (newest first).

        Returns:
            List of raw transaction dicts straight from Etherscan. Each dict
            is passed to `TransactionNormalizer` before use.

        Raises:
            EtherscanException: On API error or network failure.
        """
        params = {
            "module": "account",
            "action": "txlist",
            "address": wallet,
            "startblock": str(start_block),
            "endblock": str(end_block),
            "page": str(page),
            "offset": str(offset),
            "sort": sort,
        }
        data = await self._request(params, context={"wallet": wallet, "method": "get_transactions"})
        return self._extract_list(data, wallet, "get_transactions")

    async def get_internal_transactions(
        self,
        wallet: str,
        start_block: int = 0,
        end_block: int = 99_999_999,
        page: int = 1,
        offset: int = 1000,
        sort: str = "asc",
    ) -> list[dict[str, Any]]:
        """
        Fetch internal (contract-initiated) ETH transactions for a wallet.

        Args:
            wallet: Ethereum address.
            start_block: First block to include.
            end_block: Last block to include.
            page: Page number.
            offset: Records per page.
            sort: "asc" or "desc".

        Returns:
            List of raw internal transaction dicts.

        Raises:
            EtherscanException: On API error or network failure.
        """
        params = {
            "module": "account",
            "action": "txlistinternal",
            "address": wallet,
            "startblock": str(start_block),
            "endblock": str(end_block),
            "page": str(page),
            "offset": str(offset),
            "sort": sort,
        }
        data = await self._request(params, context={"wallet": wallet, "method": "get_internal_transactions"})
        return self._extract_list(data, wallet, "get_internal_transactions")

    async def get_token_transfers(
        self,
        wallet: str,
        start_block: int = 0,
        end_block: int = 99_999_999,
        page: int = 1,
        offset: int = 1000,
        sort: str = "asc",
    ) -> list[dict[str, Any]]:
        """
        Fetch ERC-20 token transfer events for a wallet.

        Args:
            wallet: Ethereum address.
            start_block: First block to include.
            end_block: Last block to include.
            page: Page number.
            offset: Records per page.
            sort: "asc" or "desc".

        Returns:
            List of raw token transfer dicts.

        Raises:
            EtherscanException: On API error or network failure.
        """
        params = {
            "module": "account",
            "action": "tokentx",
            "address": wallet,
            "startblock": str(start_block),
            "endblock": str(end_block),
            "page": str(page),
            "offset": str(offset),
            "sort": sort,
        }
        data = await self._request(params, context={"wallet": wallet, "method": "get_token_transfers"})
        return self._extract_list(data, wallet, "get_token_transfers")

    async def get_contract_info(self, address: str) -> dict[str, Any]:
        """
        Check whether an address is a contract and fetch its ABI if available.

        Uses the `getabi` endpoint. A 200 OK with status="0" and
        message="Contract source code not verified" means the contract exists
        but is unverified — this is still returned as a positive result.

        Args:
            address: Ethereum address to inspect.

        Returns:
            Dict with keys:
              - `is_contract` (bool): True if address has deployed bytecode.
              - `abi` (list | None): Parsed ABI if verified, else None.
              - `source_verified` (bool): True if source code is verified.

        Raises:
            EtherscanException: On network error.
        """
        # Step 1: Check if address has bytecode (proxy=contract)
        code_params = {
            "module": "proxy",
            "action": "eth_getCode",
            "address": address,
            "tag": "latest",
        }
        try:
            code_data = await self._request(
                code_params,
                context={"address": address, "method": "get_contract_info:code"},
            )
            bytecode = code_data.get("result", "0x")
            is_contract = isinstance(bytecode, str) and len(bytecode) > 2
        except EtherscanException:
            is_contract = False

        # Step 2: Try to fetch ABI (only meaningful for verified contracts)
        abi_params = {
            "module": "contract",
            "action": "getabi",
            "address": address,
        }
        try:
            abi_data = await self._request(
                abi_params,
                context={"address": address, "method": "get_contract_info:abi"},
            )
            import json as _json
            raw_abi = abi_data.get("result", "")
            if raw_abi and raw_abi != "Contract source code not verified":
                abi = _json.loads(raw_abi)
                source_verified = True
            else:
                abi = None
                source_verified = False
        except EtherscanException:
            abi = None
            source_verified = False

        return {
            "is_contract": is_contract,
            "abi": abi,
            "source_verified": source_verified,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────────────

    async def _request(self, params: dict[str, str], context: dict[str, Any]) -> dict[str, Any]:
        params["apikey"] = self._api_key
        params.setdefault("chainid", "1")  # Ethereum mainnet — V2 API requires this
        async with self._limiter:
            try:
                return await self._execute_with_retry(params, context)
            except _RetryableError as exc:
                raise EtherscanException(
                    error_code=ErrorCode.MAX_RETRIES_EXCEEDED,
                    message=(
                        f"Etherscan request failed after {self._max_retries} retries."
                    ),
                    context=context,
                    cause=exc,
                ) from exc

    async def _execute_with_retry(
        self,
        params: dict[str, str],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Retry loop honouring settings.max_retries with exponential backoff."""
        import asyncio as _asyncio
        last_err: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                return await self._single_attempt(params, context)
            except _RetryableError as exc:
                last_err = exc
                wait = self._backoff_base * (2 ** attempt)
                logger.debug("etherscan_retry", attempt=attempt+1,
                             max_retries=self._max_retries, wait_seconds=wait, **context)
                await _asyncio.sleep(wait)
        raise last_err or _RetryableError("max_retries_exhausted")

    async def _single_attempt(
        self,
        params: dict[str, str],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Single HTTP attempt — raises _RetryableError or EtherscanException."""
        try:
            response = await self._http.get(self._base_url, params=params)
        except httpx.TimeoutException as exc:
            logger.warning("etherscan_timeout", **context)
            raise _RetryableError("timeout") from exc
        except httpx.NetworkError as exc:
            logger.warning("etherscan_network_error", error=str(exc), **context)
            raise _RetryableError("network_error") from exc
        except httpx.HTTPError as exc:
            logger.warning("etherscan_http_error", error=str(exc), **context)
            raise _RetryableError("http_error") from exc

        # Handle transport-level rate limiting
        if response.status_code == 429:
            logger.warning("etherscan_rate_limited", **context)
            raise _RetryableError("rate_limited")

        # Retry on server errors
        if response.status_code >= 500:
            logger.warning("etherscan_server_error", status_code=response.status_code, **context)
            raise _RetryableError(f"server_error_{response.status_code}")

        # Non-retryable HTTP errors
        if response.status_code >= 400:
            raise EtherscanException(
                error_code=ErrorCode.ETHERSCAN_UNREACHABLE,
                message=f"Etherscan returned HTTP {response.status_code}.",
                context={**context, "status_code": response.status_code},
            )

        # Parse JSON
        try:
            data: dict[str, Any] = response.json()
        except Exception as exc:
            raise EtherscanException(
                error_code=ErrorCode.ETHERSCAN_UNREACHABLE,
                message="Etherscan returned non-JSON response.",
                context=context,
                cause=exc,
            ) from exc

        # Handle Etherscan application-level errors (HTTP 200 with status="0")
        api_status = str(data.get("status", _STATUS_OK))
        message = str(data.get("message", ""))
        result = data.get("result", "")

        if api_status == _STATUS_ERROR:
            # "Max rate limit reached" → retry
            if "rate limit" in message.lower() or "max rate" in message.lower():
                logger.warning("etherscan_api_rate_limit", message=message, **context)
                raise _RetryableError("api_rate_limit")

            # "Invalid address" → non-retryable
            if "invalid address" in message.lower():
                raise EtherscanException(
                    error_code=ErrorCode.ETHERSCAN_INVALID_ADDRESS,
                    message=f"Invalid Ethereum address: {context.get('wallet', context.get('address', '?'))}",
                    context=context,
                )

            # "No transactions found" / "No records found" → return empty list
            if _MSG_NO_TRANSACTIONS.lower() in message.lower() or _MSG_NO_RECORDS.lower() in message.lower():
                return {"status": _STATUS_OK, "message": message, "result": []}

            # All other API errors
            raise EtherscanException(
                error_code=ErrorCode.ETHERSCAN_UNREACHABLE,
                message=f"Etherscan API error: {message or result}",
                context={**context, "api_message": message, "api_result": str(result)[:200]},
            )

        return data

    def _extract_list(
        self,
        data: dict[str, Any],
        wallet: str,
        method: str,
    ) -> list[dict[str, Any]]:
        """
        Extract the `result` list from a successful Etherscan response.

        Args:
            data: Parsed Etherscan response dict.
            wallet: Wallet address (for error context).
            method: Calling method name (for error context).

        Returns:
            List of transaction/transfer dicts. Empty list if none found.

        Raises:
            EtherscanException: If `result` is not a list.
        """
        result = data.get("result", [])
        if result is None:
            return []
        if not isinstance(result, list):
            raise EtherscanException(
                error_code=ErrorCode.ETHERSCAN_UNREACHABLE,
                message=f"Expected list in Etherscan response for {method}.",
                context={"wallet": wallet, "method": method, "result_type": type(result).__name__},
            )
        return result
