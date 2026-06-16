"""
backend/api/routers/history.py
─────────────────────────────────────────────────────────────────────────────
GET /history              — paginated list of all investigations
GET /history/{wallet}     — investigations for a specific wallet

PURPOSE:
  Provides read-only access to the investigations table for history browsing.
  No write operations — this router is a thin wrapper over InvestigationRepository.
"""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.dependencies import AuthDep
from backend.persistence.database import get_db
from backend.persistence.repositories import InvestigationRepository
from backend.schemas.request import PaginationParams
from backend.schemas.response import InvestigationListResponse, InvestigationResponse
from backend.utils import is_valid_eth_address

import aiosqlite

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["History"])

DbDep = Annotated[aiosqlite.Connection, Depends(get_db)]


# ─────────────────────────────────────────────────────────────────────────────
# GET /history
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/history",
    response_model=InvestigationListResponse,
    summary="List all investigations",
    description=(
        "Returns a paginated list of all investigations, ordered by creation "
        "time descending (most recent first)."
    ),
)
async def list_all_investigations(
    db: DbDep,
    _auth: AuthDep,
    pagination: Annotated[PaginationParams, Depends()],
    status_filter: Annotated[
        str | None,
        Query(alias="status", description="Filter by status: PENDING | RUNNING | COMPLETE | FAILED"),
    ] = None,
) -> InvestigationListResponse:
    """
    Return a paginated list of all investigations.

    Args:
        pagination: Page and page_size query parameters.
        status_filter: Optional status to filter by.

    Returns:
        Paginated InvestigationListResponse.
    """
    repo = InvestigationRepository(db)

    if status_filter:
        items = await repo.list_by_status(
            status=status_filter.upper(),
            limit=pagination.limit,
            offset=pagination.offset,
        )
        total = await repo.count_by_status(status_filter.upper())
    else:
        items = await repo.list_recent(
            limit=pagination.limit,
            offset=pagination.offset,
        )
        total = await repo.count()

    return InvestigationListResponse.build(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /history/{wallet}
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/history/{wallet}",
    response_model=InvestigationListResponse,
    summary="List investigations for a wallet",
    description="Returns all investigations for the given Ethereum wallet address.",
    responses={
        400: {"description": "Invalid Ethereum address format."},
    },
)
async def list_investigations_for_wallet(
    wallet: str,
    db: DbDep,
    _auth: AuthDep,
    pagination: Annotated[PaginationParams, Depends()],
) -> InvestigationListResponse:
    """
    Return all investigations for a specific wallet, newest first.

    Args:
        wallet: Ethereum wallet address (path parameter).
        pagination: Page and page_size query parameters.

    Returns:
        Paginated InvestigationListResponse filtered to this wallet.

    Raises:
        HTTPException 400: If the wallet address format is invalid.
    """
    if not is_valid_eth_address(wallet):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Ethereum address: '{wallet}'.",
        )

    wallet_lower = wallet.lower()
    repo = InvestigationRepository(db)

    items = await repo.list_by_wallet(
        wallet_address=wallet_lower,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    total = await repo.count_by_wallet(wallet_lower)

    return InvestigationListResponse.build(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )