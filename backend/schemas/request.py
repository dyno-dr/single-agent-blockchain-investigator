"""
backend/schemas/request.py
─────────────────────────────────────────────────────────────────────────────
Pydantic request schemas for all API endpoints.

PURPOSE:
  Defines the validated, typed shapes of every request body and query-param
  model. Route handlers stay thin: they accept these schemas, pass them to
  the service/repository layer, and return response schemas.

DESIGN DECISIONS:
  1. All wallet addresses are validated and lower-cased on input via a
     field validator. Routes never see a non-normalised address.
  2. Pagination follows offset-based pagination (page + page_size) for
     simplicity. Cursor-based pagination can be layered in Phase 3+.
  3. `InvestigationRequest` carries sane defaults sourced from Settings
     defaults. Callers only need to supply `wallet_address`.
  4. Strict field constraints (`ge`, `le`, `max_length`) prevent oversized
     inputs from reaching the database or Etherscan client.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from backend.utils import is_valid_eth_address

# ─────────────────────────────────────────────────────────────────────────────
# Investigation
# ─────────────────────────────────────────────────────────────────────────────


class InvestigationRequest(BaseModel):
    """
    Request body for POST /investigate.

    All fields except `wallet_address` are optional — the backend applies
    defaults from `InvestigationDefaults` settings.

    Attributes:
        wallet_address: Target Ethereum wallet to investigate.
        depth: Trace depth (1 = direct txs only, 2 = one hop, 3 = two hops).
        lookback_days: How far back to pull transactions.
        max_transactions: Maximum transactions to fetch per wallet per hop.
    """

    wallet_address: str = Field(
        ...,
        description="Ethereum wallet address to investigate (0x-prefixed hex).",
        examples=["0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"],
    )
    depth: int = Field(
        default=2,
        ge=1,
        le=3,
        description="Trace depth. 1 = direct transactions only. 3 = two hops.",
    )
    lookback_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Number of days of transaction history to analyse.",
    )
    max_transactions: int = Field(
        default=500,
        ge=10,
        le=1000,
        description="Maximum transactions to fetch per wallet. Capped at 1000.",
    )

    @field_validator("wallet_address", mode="before")
    @classmethod
    def validate_and_normalise_address(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("wallet_address must be a string.")
        if not is_valid_eth_address(v):
            raise ValueError(
                f"Invalid Ethereum address: '{v}'. "
                "Must be a 0x-prefixed 40-character hexadecimal string."
            )
        return v.lower()

    model_config = {
        "json_schema_extra": {
            "example": {
                "wallet_address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                "depth": 2,
                "lookback_days": 90,
                "max_transactions": 500,
            }
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pagination
# ─────────────────────────────────────────────────────────────────────────────


class PaginationParams(BaseModel):
    """
    Common pagination query parameters injected via FastAPI Depends().

    Usage in a route:
        @router.get("/history")
        async def list_history(pagination: PaginationParams = Depends()):
            ...

    Attributes:
        page: 1-based page number.
        page_size: Items per page (1–100).
    """

    page: Annotated[int, Field(default=1, ge=1, description="1-based page number.")]
    page_size: Annotated[
        int,
        Field(default=20, ge=1, le=100, description="Items per page (max 100)."),
    ]

    @property
    def offset(self) -> int:
        """Zero-based SQL offset."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """SQL LIMIT value (alias for page_size)."""
        return self.page_size
