"""
backend/schemas/response.py
─────────────────────────────────────────────────────────────────────────────
Pydantic response schemas for investigation and error endpoints.

PURPOSE:
  Defines the typed shapes of every API response. Route handlers construct
  instances of these schemas; FastAPI serialises them to JSON automatically.

DESIGN DECISIONS:
  1. All datetime fields are serialised as ISO 8601 UTC strings for
     consistent frontend parsing.
  2. `InvestigationResponse` mirrors the `investigations` table shape so
     repositories can construct it directly from row dicts.
  3. `ErrorResponse` provides a consistent error envelope across all routes.
     The global exception handler in main.py constructs this shape.
  4. Pagination metadata is embedded in list responses (`total`, `page`,
     `page_size`) so clients can implement "load more" without an extra
     count request.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Investigation
# ─────────────────────────────────────────────────────────────────────────────


class InvestigationResponse(BaseModel):
    """
    Response shape for a single investigation record.

    Returned by:
        POST /investigate          → newly created investigation
        GET  /investigate/{id}     → existing investigation
        GET  /history              → list item
        GET  /history/{wallet}     → list item
    """

    id: str = Field(description="UUID4 investigation session ID.")
    wallet_address: str = Field(description="Ethereum address under investigation.")
    status: str = Field(description="Lifecycle status: PENDING | RUNNING | COMPLETE | FAILED.")
    phase: str | None = Field(default=None, description="Current agent phase (last completed node).")
    created_at: str = Field(description="ISO 8601 UTC creation timestamp.")
    started_at: str | None = Field(default=None, description="ISO 8601 UTC execution start timestamp.")
    completed_at: str | None = Field(default=None, description="ISO 8601 UTC completion timestamp.")
    depth: int = Field(description="Trace depth requested (1–3).")
    lookback_days: int = Field(description="Transaction lookback window in days.")
    max_transactions: int = Field(description="Max transactions fetched per wallet.")
    risk_score: float | None = Field(default=None, description="Computed risk score (0.0–100.0).")
    risk_level: str | None = Field(default=None, description="Risk level: LOW | MEDIUM | HIGH | CRITICAL.")
    error_message: str | None = Field(default=None, description="Failure reason (only on FAILED status).")
    error_code: str | None = Field(default=None, description="Machine-readable error code (only on FAILED status).")
    chain: str = Field(default="ETHEREUM", description="Blockchain network.")
    request_id: str | None = Field(default=None, description="HTTP request ID for log correlation.")

    model_config = {"from_attributes": True}


class InvestigationListResponse(BaseModel):
    """
    Paginated list of investigations.

    Returned by GET /history and GET /history/{wallet}.
    """

    items: list[InvestigationResponse] = Field(description="Investigation records for this page.")
    total: int = Field(description="Total number of investigations matching the query.")
    page: int = Field(description="Current 1-based page number.")
    page_size: int = Field(description="Items per page.")
    pages: int = Field(description="Total number of pages.")

    @classmethod
    def build(
        cls,
        items: list[dict[str, Any]],
        total: int,
        page: int,
        page_size: int,
    ) -> "InvestigationListResponse":
        """
        Construct a paginated response from a list of raw row dicts.

        Args:
            items: Raw investigation row dicts from the repository.
            total: Total count of matching records.
            page: Current page number (1-based).
            page_size: Items per page.

        Returns:
            Populated InvestigationListResponse.
        """
        import math
        return cls(
            items=[InvestigationResponse(**row) for row in items],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)) if total > 0 else 1,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Error
# ─────────────────────────────────────────────────────────────────────────────


class ErrorResponse(BaseModel):
    """
    Standard error envelope returned by all error responses.

    Constructed by the global exception handler in main.py. All API errors
    share this shape regardless of the source exception type.
    """

    error: str = Field(description="Machine-readable error code or HTTP status label.")
    message: str = Field(description="Human-readable error description.")
    request_id: str = Field(description="Request ID for log correlation.")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context (wallet address, session ID, etc.).",
    )
    timestamp: str = Field(description="ISO 8601 UTC timestamp when the error occurred.")

    model_config = {"from_attributes": True}