"""
backend/persistence/repositories/report_repo.py
─────────────────────────────────────────────────────────────────────────────
Repository for the `reports` table.

PURPOSE:
  Owns all SQL operations against the `reports` table. Each row represents
  the final LLM-generated report for one completed investigation. The 1:1
  relationship between investigations and reports is enforced both by a
  UNIQUE constraint in the schema and by a pre-flight existence check here.

QUERY PATTERNS:
  create(...)                   → INSERT a new report row
  get(id)                       → SELECT by primary key
  get_by_investigation(inv_id)  → SELECT by investigation_id (1:1 lookup)
  list_recent(...)              → SELECT most recent N reports
  list_by_risk_level(...)       → SELECT reports filtered by risk_level
  update_graph_data(...)        → UPDATE graph_data blob after visualization
  delete(id)                    → DELETE by primary key (admin)
  exists_for_investigation(id)  → Quick existence check
  count(...)                    → COUNT reports, optionally by risk_level

DESIGN DECISIONS:
  1. `create` checks for a pre-existing report and raises RepositoryException
     instead of letting SQLite raise a UNIQUE constraint violation, providing
     a cleaner structured error for callers.
  2. JSON fields (findings_json, recommendations_json, graph_data) are
     deserialised on every read via `_deserialise_report`. Callers always
     receive Python objects, never raw JSON strings.
  3. `risk_score` is stored as TEXT (decimal string) to avoid float precision
     loss. Callers pass `str(float_score)`; the repository stores it verbatim.
  4. `update_graph_data` is a separate method because graph serialisation is
     expensive and happens asynchronously after initial report creation.
  5. `model_used` stores the LLM model string for audit reproducibility.
"""

from __future__ import annotations

from typing import Any
import uuid

import structlog

from backend.constants import ErrorCode
from backend.exceptions import RepositoryException
from backend.persistence.repositories.base import BaseRepository

logger = structlog.get_logger(__name__)


class ReportRepository(BaseRepository):
    """
    Data access layer for the `reports` table.

    Args:
        conn: Open aiosqlite.Connection injected via FastAPI Depends(get_db).
    """

    TABLE = "reports"

    # ─────────────────────────────────────────────────────────────────────────
    # Write operations
    # ─────────────────────────────────────────────────────────────────────────

    async def create(
        self,
        *,
        investigation_id: str,
        title: str,
        summary: str,
        findings: list[dict[str, Any]],
        risk_score: float,
        risk_level: str,
        evidence_count: int,
        recommendations: list[str] | None = None,
        graph_data: dict[str, Any] | None = None,
        model_used: str | None = None,
    ) -> dict[str, Any]:
        """
        Insert a new report for a completed investigation.

        Args:
            investigation_id: UUID of the parent investigation.
            title:            Generated report title.
            summary:          LLM-generated executive summary paragraph.
            findings:         List of structured finding dicts.
            risk_score:       Final risk score (0.0–100.0).
            risk_level:       RiskLevel enum value: LOW|MEDIUM|HIGH|CRITICAL.
            evidence_count:   Total evidence items linked to this report.
            recommendations:  Optional list of recommendation strings.
            graph_data:       Optional serialised graph (nodes + edges).
            model_used:       Optional LLM model string for audit.

        Returns:
            Newly inserted report dict with JSON fields deserialised.

        Raises:
            RepositoryException: If a report already exists for this
                investigation_id.
        """
        if await self.exists_for_investigation(investigation_id):
            raise RepositoryException(
                message=(
                    f"A report already exists for investigation "
                    f"'{investigation_id}'. Each investigation may have at "
                    "most one report."
                ),
                operation="create",
                table=self.TABLE,
                record_id=investigation_id,
                error_code=ErrorCode.DATABASE_WRITE_FAILED,
            )

        report_id = str(uuid.uuid4())
        now = self._utc_now()

        await self._conn.execute(
            """
            INSERT INTO reports (
                id, investigation_id,
                title, summary, findings_json, recommendations_json, graph_data,
                risk_score, risk_level, evidence_count,
                generated_at, model_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                investigation_id,
                title,
                summary,
                self._dump_json(findings),
                self._dump_json(recommendations),
                self._dump_json(graph_data),
                str(risk_score),
                risk_level,
                evidence_count,
                now,
                model_used,
            ),
        )
        await self._conn.commit()

        logger.info(
            "report_created",
            report_id=report_id,
            investigation_id=investigation_id,
            risk_level=risk_level,
            evidence_count=evidence_count,
        )

        row = await self.get(report_id)
        assert row is not None  # just inserted — must exist
        return row

    async def update_graph_data(
        self,
        report_id: str,
        graph_data: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Attach serialised graph data to an existing report.

        Called by the visualization layer after the initial report is created.
        Graph serialisation is computationally expensive and is performed
        asynchronously after report generation.

        Args:
            report_id:  UUID of the report to update.
            graph_data: Dict with `nodes` and `edges` lists.

        Returns:
            Updated report dict, or None if report_id not found.
        """
        await self._conn.execute(
            """
            UPDATE reports
            SET graph_data = ?
            WHERE id = ?
            """,
            (self._dump_json(graph_data), report_id),
        )
        await self._conn.commit()
        return await self.get(report_id)

    async def delete(self, report_id: str) -> bool:
        """
        Delete a report by primary key.

        Args:
            report_id: UUID of the report to delete.

        Returns:
            True if a row was deleted, False if not found.
        """
        cursor = await self._conn.execute(
            "DELETE FROM reports WHERE id = ?",
            (report_id,),
        )
        await self._conn.commit()
        return cursor.rowcount > 0

    # ─────────────────────────────────────────────────────────────────────────
    # Read operations
    # ─────────────────────────────────────────────────────────────────────────

    async def get(self, report_id: str) -> dict[str, Any] | None:
        """
        Fetch a single report by primary key.

        Args:
            report_id: UUID to look up.

        Returns:
            Report dict with JSON fields deserialised, or None.
        """
        async with self._conn.execute(
            "SELECT * FROM reports WHERE id = ?",
            (report_id,),
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            return None

        return self._deserialise_report(self._row_to_dict(row))

    async def get_by_investigation(
        self,
        investigation_id: str,
    ) -> dict[str, Any] | None:
        """
        Fetch the report for a specific investigation (1:1 lookup).

        Args:
            investigation_id: UUID of the parent investigation.

        Returns:
            Report dict with JSON fields deserialised, or None if no report
            yet exists for this investigation.
        """
        async with self._conn.execute(
            "SELECT * FROM reports WHERE investigation_id = ?",
            (investigation_id,),
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            return None

        return self._deserialise_report(self._row_to_dict(row))

    async def list_recent(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List the most recently generated reports.

        Args:
            limit:  Max rows (default 20).
            offset: Pagination offset (default 0).

        Returns:
            List of report dicts, newest first.
        """
        async with self._conn.execute(
            """
            SELECT * FROM reports
            ORDER BY generated_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()

        return [self._deserialise_report(self._row_to_dict(r)) for r in rows]

    async def list_by_risk_level(
        self,
        risk_level: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List reports filtered by risk level.

        Args:
            risk_level: RiskLevel enum value: LOW|MEDIUM|HIGH|CRITICAL.
            limit:      Max rows (default 20).
            offset:     Pagination offset (default 0).

        Returns:
            List of report dicts, newest first.
        """
        async with self._conn.execute(
            """
            SELECT * FROM reports
            WHERE risk_level = ?
            ORDER BY generated_at DESC
            LIMIT ? OFFSET ?
            """,
            (risk_level, limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()

        return [self._deserialise_report(self._row_to_dict(r)) for r in rows]

    async def exists_for_investigation(self, investigation_id: str) -> bool:
        """
        Check whether a report already exists for an investigation.

        Args:
            investigation_id: UUID of the parent investigation.

        Returns:
            True if a report row exists, False otherwise.
        """
        async with self._conn.execute(
            "SELECT 1 FROM reports WHERE investigation_id = ? LIMIT 1",
            (investigation_id,),
        ) as cursor:
            row = await cursor.fetchone()
        return row is not None

    async def count(self, *, risk_level: str | None = None) -> int:
        """
        Return the total number of reports, optionally filtered by risk level.

        Args:
            risk_level: Optional RiskLevel filter.

        Returns:
            Integer count.
        """
        if risk_level:
            async with self._conn.execute(
                "SELECT COUNT(*) FROM reports WHERE risk_level = ?",
                (risk_level,),
            ) as cursor:
                row = await cursor.fetchone()
        else:
            async with self._conn.execute(
                "SELECT COUNT(*) FROM reports"
            ) as cursor:
                row = await cursor.fetchone()

        return row[0] if row else 0

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _deserialise_report(self, row: dict[str, Any]) -> dict[str, Any]:
        """
        Deserialise JSON blob columns in a report row dict.

        Converts findings_json, recommendations_json, and graph_data from
        raw TEXT strings to Python objects. Called on every read operation
        so callers never handle raw JSON.

        Args:
            row: Raw dict from `_row_to_dict`.

        Returns:
            Row dict with JSON columns deserialised.
        """
        row["findings_json"] = self._load_json(row.get("findings_json"))
        row["recommendations_json"] = self._load_json(row.get("recommendations_json"))
        row["graph_data"] = self._load_json(row.get("graph_data"))
        return row
