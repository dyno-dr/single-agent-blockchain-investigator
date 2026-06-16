"""
backend/utils.py
─────────────────────────────────────────────────────────────────────────────
Shared utility functions used across the entire backend.

PURPOSE:
  Pure, stateless helper functions with no dependencies on application state,
  database, or external services. Every function is independently testable.

DESIGN DECISIONS:
  1. No imports from backend.settings or backend.dependencies — utils must
     not create circular imports. Accept configuration as function parameters
     where needed.
  2. Ethereum address validation follows EIP-55 checksum standard. The
     Etherscan API returns checksummed addresses; we validate input addresses
     before spawning any investigation.
  3. `utc_now()` is the single source of UTC time throughout the app.
     Using datetime.utcnow() directly in business logic creates hidden
     timezone assumptions. All timestamps in DB and API responses are UTC.

FUTURE SCALABILITY:
  - Add `validate_bitcoin_address()` when Phase 3 multi-chain support lands.
  - Add `calculate_usd_value()` when price oracle integration ships.
  - Pagination helpers will expand with cursor-based pagination for Phase 2+.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import re
from typing import TypeVar
import uuid

T = TypeVar("T")


# ─────────────────────────────────────────────────────────────────────────────
# Time
# ─────────────────────────────────────────────────────────────────────────────


def utc_now() -> datetime:
    """
    Return the current UTC datetime as a timezone-aware object.

    Always use this instead of datetime.utcnow() (which returns a naive
    datetime) or datetime.now() (which uses local time).
    """
    return datetime.now(UTC)


def utc_now_iso() -> str:
    """Return the current UTC datetime as an ISO 8601 string."""
    return utc_now().isoformat()


def unix_to_utc(unix_timestamp: int | float) -> datetime:
    """Convert a Unix epoch timestamp (seconds) to a UTC-aware datetime."""
    return datetime.fromtimestamp(unix_timestamp, tz=UTC)


def utc_to_unix(dt: datetime) -> int:
    """Convert a datetime to a Unix epoch timestamp (integer seconds)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


# ─────────────────────────────────────────────────────────────────────────────
# Identity
# ─────────────────────────────────────────────────────────────────────────────


def generate_session_id() -> str:
    """Generate a random UUID4 string for investigation session IDs."""
    return str(uuid.uuid4())


def generate_report_id() -> str:
    """Generate a random UUID4 string for report IDs."""
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Ethereum Address Validation
# ─────────────────────────────────────────────────────────────────────────────

# Regex: 0x followed by exactly 40 hex characters (case-insensitive)
_ETH_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_valid_eth_address(address: str) -> bool:
    """
    Validate an Ethereum address.

    Accepts both checksummed (EIP-55) and lower/uppercase addresses.
    The address is structurally valid if it matches the hex pattern.

    Args:
        address: Ethereum address string to validate.

    Returns:
        True if the address is structurally valid, False otherwise.
    """
    if not isinstance(address, str):
        return False
    return bool(_ETH_ADDRESS_PATTERN.match(address))


def to_checksum_address(address: str) -> str:
    """
    Convert an Ethereum address to its EIP-55 checksummed form.

    Uses eth_utils if available; falls back to lowercase with 0x prefix.
    The blockchain layer will always have eth_utils available; this fallback
    only fires in isolated unit tests of this module.

    Args:
        address: Valid Ethereum address (0x-prefixed, any case).

    Returns:
        EIP-55 checksummed address.

    Raises:
        ValueError: If address is not a valid Ethereum address.
    """
    if not is_valid_eth_address(address):
        raise ValueError(f"Invalid Ethereum address: {address!r}")

    try:
        from eth_utils import to_checksum_address as _eth_checksum
        return _eth_checksum(address)
    except ImportError:
        # Fallback: return lowercase with 0x prefix (valid, not checksummed).
        # eth_utils is added with the blockchain layer in a later phase.
        return "0x" + address[2:].lower()


def normalize_address(address: str) -> str:
    """
    Normalize an Ethereum address to lowercase with 0x prefix.

    Used for database storage and comparison. EIP-55 checksumming is applied
    at validation time (API input); internal comparisons use lowercase.

    Args:
        address: Ethereum address string.

    Returns:
        Lowercase 0x-prefixed address.

    Raises:
        ValueError: If address is not valid.
    """
    if not is_valid_eth_address(address):
        raise ValueError(f"Invalid Ethereum address: {address!r}")
    return address.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Transaction Hash Validation
# ─────────────────────────────────────────────────────────────────────────────

_TX_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


def is_valid_tx_hash(tx_hash: str) -> bool:
    """
    Validate an Ethereum transaction hash.

    Args:
        tx_hash: Transaction hash string to validate.

    Returns:
        True if the hash is structurally valid (0x + 64 hex chars).
    """
    if not isinstance(tx_hash, str):
        return False
    return bool(_TX_HASH_PATTERN.match(tx_hash))


# ─────────────────────────────────────────────────────────────────────────────
# Numeric Utilities
# ─────────────────────────────────────────────────────────────────────────────


def wei_to_eth(wei: int) -> float:
    """Convert Wei (smallest ETH unit) to ETH."""
    return wei / 1_000_000_000_000_000_000  # 10^18


def eth_to_wei(eth: float) -> int:
    """Convert ETH to Wei."""
    return int(eth * 1_000_000_000_000_000_000)


def gwei_to_eth(gwei: float) -> float:
    """Convert Gwei to ETH."""
    return gwei / 1_000_000_000  # 10^9


def clamp(value: float, min_val: float, max_val: float) -> float:
    """Clamp a float value to [min_val, max_val]."""
    return max(min_val, min(max_val, value))


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Divide numerator by denominator, returning `default` on ZeroDivisionError.
    Prevents crashes in scoring calculations where wallet balance may be zero.
    """
    if denominator == 0.0:
        return default
    return numerator / denominator


# ─────────────────────────────────────────────────────────────────────────────
# String Utilities
# ─────────────────────────────────────────────────────────────────────────────


def truncate(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate a string to max_length, appending suffix if truncated.

    Used when storing agent reasoning steps to prevent DB row bloat.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def mask_api_key(key: str) -> str:
    """
    Mask an API key for safe logging.
    Returns first 4 chars + '****' + last 4 chars.
    """
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}****{key[-4:]}"


# ─────────────────────────────────────────────────────────────────────────────
# Pagination
# ─────────────────────────────────────────────────────────────────────────────


def calculate_offset(page: int, page_size: int) -> int:
    """
    Calculate SQL OFFSET from 1-based page number and page_size.

    Args:
        page: 1-based page number.
        page_size: Number of items per page.

    Returns:
        Zero-based offset for SQL LIMIT/OFFSET queries.
    """
    return max(0, (page - 1)) * page_size


def paginate_list[T](items: list[T], limit: int, offset: int) -> list[T]:
    """
    Paginate an in-memory list.

    Used in tests and small result sets. Production pagination happens in SQL.
    """
    return items[offset : offset + limit]


# ─────────────────────────────────────────────────────────────────────────────
# Hashing (for cache keys and deduplication)
# ─────────────────────────────────────────────────────────────────────────────


def short_hash(value: str) -> str:
    """
    Return a 12-character hex hash of the input string.
    Used for short cache keys and log correlation IDs.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:12]
