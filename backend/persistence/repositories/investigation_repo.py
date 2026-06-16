"""
backend/persistence/repositories/investigation_repo.py
─────────────────────────────────────────────────────────────────────────────
Repository for the `investigations` table.

PURPOSE:
  Owns all SQL operations against the `investigations` table. Exposes a clean
  async interface returning plain Python dicts. Route handlers and agent nodes
  interact with this class — never with raw SQL.

QUERY PATTERNS:
  create(...)         → INSERT a new PENDING investigation row
  get(id)             → SELECT by primary key
  list_by_wallet(...) → SELECT paginated rows for a wallet address
  list_recent(...)    → SELECT most recent N investigations across all wallets
  update_status(...)  → UPDATE status + phase + timestamps atomically
  update_risk(...)    → UPDATE risk_score + risk_level after scoring
  save_reasoning(...)  → UPDATE reasoning_log blob
  mark_failed(...)    → UPDATE to FAILED + error_message + error_code
  delete(id)          → DELETE by primary key (used in tests / admin)
  count()             → SELECT COUNT(*) for health/metrics

DESIGN DECISIONS:
  1. Each method issues exactly one SQL statement. No method chains multiple
     statements without an explicit transaction comment explaining why.
  2. All returned values are plain dicts (column name → value). JSON blob
     columns (reasoning_log) are deserialised by `_load_json` before return
     so callers never handle raw TEXT.
  3. `update_status` is the only method that touches lifecycle timestamps
     (started_at, completed_at). This prevents timestamp inconsistencies from
     callers that update status without updating timestamps.
  4. `list_by_wallet` and `list_recent` accept `limit` and `offset` for
     pagination. Default limit is 20 to prevent large payloads on unconstrained
     queries.
  5. All UPDATE methods return the updated row (via a follow-up SELECT) so
     callers always have the current state without issuing a second query.
"""

from __future__ import annotations

from typing import Any
import uuid

import structlog

from backend.persistence.repositories.base import BaseRepository

logger = structlog.get_logger(__name__)


class InvestigationRepository(BaseRepository):
    """
    Data access layer for the `investigations` table.

    Args:
        conn: Open aiosqlite.Connection injected via FastAPI Depends(get_db).
    """

    TABLE = "investigations"

    # ─────────────────────────────────────────────────────────────────────────
    # Write operations
    # ─────────────────────────────────────────────────────────────────────────

    async def create(
        self,
        *,
        wallet_address: str,
        depth: int = 2,
        lookback_days: int = 90,
        max_transactions: int = 500,
        chain: str = "ETHEREUM",
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Insert a new investigation row with PENDING status.

        Args:
            wallet_address:   EIP-55 checksummed Ethereum address.
            depth:            Trace depth (1–3). Defaults to 2.
            lookback_days:    Transaction lookback window. Defaults to 90.
            max_transactions: Max transactions to fetch. Defaults to 500.
            chain:            Chain identifier. Defaults to "ETHEREUM".
            request_id:       HTTP request_id for log correlation.

        Returns:
            The newly inserted investigation as a dict.
        """
        investigation_id = str(uuid.uuid4())
        now = self._utc_now()

        await self._conn.execute(
            """
            INSERT INTO investigations (
                id, wallet_address, status, created_at,
                depth, lookback_days, max_transactions,
                chain, request_id
            ) VALUES (?, ?, 'PENDING', ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                wallet_address,
                now,
                depth,
                lookback_days,
                max_transactions,
                chain,
                request_id,
            ),
        )
        await self._conn.commit()

        logger.info(
            "investigation_created",
            investigation_id=investigation_id,
            wallet_address=wallet_address,
        )

        row = await self.get(investigation_id)
        assert row is not None  # just inserted — must exist
        return row


    async def update_risk(
        self,
        investigation_id: str,
        *,
        risk_score: float,
        risk_level: str,
    ) -> dict[str, Any] | None:
        """
        Persist the risk score and level after the scoring step.

        Args:
            investigation_id: UUID of the investigation to update.
            risk_score:       Computed score (0.0–100.0).
            risk_level:       RiskLevel enum value string.

        Returns:
            Updated investigation dict, or None if ID not found.
        """
        await self._conn.execute(
            """
            UPDATE investigations
            SET risk_score = ?,
                risk_level = ?
            WHERE id = ?
            """,
            (str(risk_score), risk_level, investigation_id),
        )
        await self._conn.commit()
        return await self.get(investigation_id)

    async def save_reasoning(
        self,
        investigation_id: str,
        reasoning_log: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Persist the agent's reasoning log blob.

        Called by the MEMORY node at investigation completion.

        Args:
            investigation_id: UUID of the investigation.
            reasoning_log:    List of reasoning step dicts.

        Returns:
            Updated investigation dict, or None if ID not found.
        """
        await self._conn.execute(
            """
            UPDATE investigations
            SET reasoning_log = ?
            WHERE id = ?
            """,
            (self._dump_json(reasoning_log), investigation_id),
        )
        await self._conn.commit()
        return await self.get(investigation_id)

    async def mark_failed(
        self,
        investigation_id: str,
        *,
        error_message: str,
        error_code: str | None = None,
        phase: str | None = None,
    ) -> dict[str, Any] | None:
        """
        Mark an investigation as FAILED with an error message.

        Sets `completed_at` to now, status to FAILED, and stores the error.

        Args:
            investigation_id: UUID of the investigation.
            error_message:    Human-readable failure reason.
            error_code:       ErrorCode enum value (optional).
            phase:            Phase where failure occurred (optional).

        Returns:
            Updated investigation dict, or None if ID not found.
        """
        now = self._utc_now()

        await self._conn.execute(
            """
            UPDATE investigations
            SET status        = 'FAILED',
                phase         = COALESCE(?, phase),
                completed_at  = ?,
                error_message = ?,
                error_code    = ?
            WHERE id = ?
            """,
            (phase, now, error_message, error_code, investigation_id),
        )
        await self._conn.commit()
        return await self.get(investigation_id)

    async def delete(self, investigation_id: str) -> bool:
        """
        Delete an investigation and all its evidence/reports (CASCADE).

        Args:
            investigation_id: UUID of the investigation to delete.

        Returns:
            True if a row was deleted, False if ID was not found.
        """
        cursor = await self._conn.execute(
            "DELETE FROM investigations WHERE id = ?",
            (investigation_id,),
        )
        await self._conn.commit()
        return cursor.rowcount > 0

    # ─────────────────────────────────────────────────────────────────────────
    # Read operations
    # ─────────────────────────────────────────────────────────────────────────

    async def get(self, investigation_id: str) -> dict[str, Any] | None:
        """
        Fetch a single investigation by primary key.

        Args:
            investigation_id: UUID to look up.

        Returns:
            Investigation dict with reasoning_log deserialised, or None.
        """
        async with self._conn.execute(
            "SELECT * FROM investigations WHERE id = ?",
            (investigation_id,),
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            return None

        result = self._row_to_dict(row)
        result["reasoning_log"] = self._load_json(result.get("reasoning_log"))
        return result

    async def list_by_wallet(
        self,
        wallet_address: str,
        *,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        List investigations for a specific wallet address.

        Args:
            wallet_address: Ethereum address to filter by.
            limit:          Max rows to return (default 20).
            offset:         Pagination offset (default 0).
            status:         Optional status filter (e.g. "COMPLETE").

        Returns:
            List of investigation dicts, newest first.
        """
        if status:
            async with self._conn.execute(
                """
                SELECT * FROM investigations
                WHERE wallet_address = ? AND status = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (wallet_address, status, limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with self._conn.execute(
                """
                SELECT * FROM investigations
                WHERE wallet_address = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (wallet_address, limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()

        results = self._rows_to_dicts(rows)
        for r in results:
            r["reasoning_log"] = self._load_json(r.get("reasoning_log"))
        return results

    async def list_recent(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        List the most recent investigations across all wallets.

        Args:
            limit:  Max rows to return (default 20).
            offset: Pagination offset (default 0).
            status: Optional status filter.

        Returns:
            List of investigation dicts, newest first.
        """
        if status:
            async with self._conn.execute(
                """
                SELECT * FROM investigations
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (status, limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with self._conn.execute(
                """
                SELECT * FROM investigations
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ) as cursor:
                rows = await cursor.fetchall()

        results = self._rows_to_dicts(rows)
        for r in results:
            r["reasoning_log"] = self._load_json(r.get("reasoning_log"))
        return results

    async def count(self, *, status: str | None = None) -> int:
        """
        Return the total number of investigations, optionally filtered by status.

        Args:
            status: Optional InvestigationStatus value to filter by.

        Returns:
            Integer count.
        """
        if status:
            async with self._conn.execute(
                "SELECT COUNT(*) FROM investigations WHERE status = ?",
                (status,),
            ) as cursor:
                row = await cursor.fetchone()
        else:
            async with self._conn.execute(
                "SELECT COUNT(*) FROM investigations"
            ) as cursor:
                row = await cursor.fetchone()

        return row[0] if row else 0
    async def update_phase(
        self,
        investigation_id: str,
        *,
        phase: str,
    ) -> dict[str, Any] | None:
        """
        Update only the `phase` field of an investigation.

        Called by the background pipeline to update the current agent phase
        without changing the status or timestamps.

        Args:
            investigation_id: UUID of the investigation.
            phase:            Phase enum value string (e.g. "TX_FETCH", "DONE").

        Returns:
            Updated investigation dict, or None if ID not found.
        """
        await self._conn.execute(
            "UPDATE investigations SET phase = ? WHERE id = ?",
            (phase, investigation_id),
        )
        await self._conn.commit()
        return await self.get(investigation_id)

    async def list_by_status(
        self,
        status: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List investigations filtered by status, newest first.

        Args:
            status: InvestigationStatus value (PENDING|RUNNING|COMPLETE|FAILED).
            limit:  Max rows to return.
            offset: Pagination offset.

        Returns:
            List of investigation dicts.
        """
        async with self._conn.execute(
            """
            SELECT * FROM investigations
            WHERE status = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (status, limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()

        results = self._rows_to_dicts(rows)
        for r in results:
            r["reasoning_log"] = self._load_json(r.get("reasoning_log"))
        return results

    async def count_by_status(self, status: str) -> int:
        """
        Count investigations with the given status.

        Args:
            status: InvestigationStatus value to filter by.

        Returns:
            Integer count.
        """
        async with self._conn.execute(
            "SELECT COUNT(*) FROM investigations WHERE status = ?",
            (status,),
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def count_by_wallet(self, wallet_address: str) -> int:
        """
        Count investigations for a specific wallet address.

        Args:
            wallet_address: Ethereum address (lowercase).

        Returns:
            Integer count.
        """
        async with self._conn.execute(
            "SELECT COUNT(*) FROM investigations WHERE wallet_address = ?",
            (wallet_address,),
        ) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0

    async def update_status(
        self,
        investigation_id: str,
        *,
        status: str,
        phase: str | None = None,
        risk_score: float | None = None,
        risk_level: str | None = None,
    ) -> dict[str, Any] | None:
        """
        Update status (and optionally phase and risk) of an investigation.
        Overrides the base update_status to also accept risk_score/risk_level
        so the background pipeline can complete the investigation in one call.

        NOTE: This replaces the existing update_status in investigation_repo.py.
        If you want a clean additive change, keep the original update_status
        and add a separate update_status_with_risk method. The version shown
        here adds optional risk params to the existing signature (backwards
        compatible since all new args have defaults).
        """
        now = self._utc_now()

        if risk_score is not None and risk_level is not None:
            await self._conn.execute(
                """
                UPDATE investigations
                SET status       = ?,
                    phase        = COALESCE(?, phase),
                    started_at   = CASE WHEN status != 'RUNNING' AND ? = 'RUNNING' THEN ? ELSE started_at END,
                    completed_at = CASE WHEN ? IN ('COMPLETE', 'FAILED') THEN ? ELSE completed_at END,
                    risk_score   = ?,
                    risk_level   = ?
                WHERE id = ?
                """,
                (status, phase, status, now, status, now, str(risk_score), risk_level, investigation_id),
            )
        else:
            await self._conn.execute(
                """
                UPDATE investigations
                SET status       = ?,
                    phase        = COALESCE(?, phase),
                    started_at   = CASE WHEN status != 'RUNNING' AND ? = 'RUNNING' THEN ? ELSE started_at END,
                    completed_at = CASE WHEN ? IN ('COMPLETE', 'FAILED') THEN ? ELSE completed_at END
                WHERE id = ?
                """,
                (status, phase, status, now, status, now, investigation_id),
            )

        await self._conn.commit()
        return await self.get(investigation_id)
