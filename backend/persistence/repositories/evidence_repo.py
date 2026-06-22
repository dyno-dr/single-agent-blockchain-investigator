"""
backend/persistence/repositories/evidence_repo.py
Repository for the evidence table.
"""

from __future__ import annotations

from typing import Any
import uuid

import structlog

from backend.persistence.repositories.base import BaseRepository

logger = structlog.get_logger(__name__)

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class EvidenceRepository(BaseRepository):
    """Data access layer for the evidence table."""

    TABLE = "evidence"

    async def create(
        self, *, investigation_id: str, rule_id: str, rule_name: str,
        severity: str, description: str, wallet_address: str,
        rule_category: str | None = None, details: dict | None = None,
        reasoning: str | None = None,
        tx_hash: str | None = None, block_number: int | None = None,
        value_eth: str | None = None,
    ) -> dict[str, Any]:
        """Insert a single evidence item."""
        evidence_id = str(uuid.uuid4())
        now = self._utc_now()
        await self._conn.execute(
            """
            INSERT INTO evidence (
                id, investigation_id, rule_id, rule_name, rule_category,
                severity, description, reasoning, details,
                wallet_address, tx_hash, block_number, value_eth, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (evidence_id, investigation_id, rule_id, rule_name, rule_category,
             severity, description, reasoning, self._dump_json(details),
             wallet_address, tx_hash, block_number, value_eth, now),
        )
        await self._conn.commit()
        logger.info("evidence_created", evidence_id=evidence_id,
                    investigation_id=investigation_id, rule_id=rule_id, severity=severity)
        row = await self.get(evidence_id)
        assert row is not None
        return row

    async def create_batch(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Insert multiple evidence items in a single transaction."""
        if not items:
            return []
        now = self._utc_now()
        inserted_ids: list[str] = []
        for item in items:
            evidence_id = str(uuid.uuid4())
            inserted_ids.append(evidence_id)
            await self._conn.execute(
                """
                INSERT INTO evidence (
                    id, investigation_id, rule_id, rule_name, rule_category,
                    severity, description, reasoning, details,
                    wallet_address, tx_hash, block_number, value_eth, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (evidence_id, item["investigation_id"], item["rule_id"], item["rule_name"],
                 item.get("rule_category"), item["severity"], item["description"],
                 item.get("reasoning"), self._dump_json(item.get("details")),
                 item["wallet_address"],
                 item.get("tx_hash"), item.get("block_number"), item.get("value_eth"), now),
            )
        await self._conn.commit()
        logger.info("evidence_batch_created", count=len(items))
        results = []
        for eid in inserted_ids:
            row = await self.get(eid)
            if row:
                results.append(row)
        return results

    async def delete_by_investigation(self, investigation_id: str) -> int:
        """Delete all evidence for a given investigation."""
        cursor = await self._conn.execute(
            "DELETE FROM evidence WHERE investigation_id = ?", (investigation_id,))
        await self._conn.commit()
        return cursor.rowcount

    async def get(self, evidence_id: str) -> dict[str, Any] | None:
        """Fetch a single evidence item by primary key."""
        async with self._conn.execute(
            "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        result = self._row_to_dict(row)
        result["details"] = self._load_json(result.get("details"))
        return result

    async def list_by_investigation(
        self, investigation_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List all evidence for an investigation, severity-first."""
        async with self._conn.execute(
            """
            SELECT * FROM evidence WHERE investigation_id = ?
            ORDER BY
                CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                              WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
                detected_at DESC
            LIMIT ? OFFSET ?
            """,
            (investigation_id, limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
        results = self._rows_to_dicts(rows)
        for r in results:
            r["details"] = self._load_json(r.get("details"))
        return results

    async def list_by_rule(
        self, rule_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List all evidence items for a given rule_id."""
        async with self._conn.execute(
            """
            SELECT * FROM evidence WHERE rule_id = ?
            ORDER BY detected_at DESC LIMIT ? OFFSET ?
            """,
            (rule_id, limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
        results = self._rows_to_dicts(rows)
        for r in results:
            r["details"] = self._load_json(r.get("details"))
        return results

    async def list_by_wallet(
        self, wallet_address: str, *, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List all evidence for a wallet across all investigations."""
        async with self._conn.execute(
            """
            SELECT * FROM evidence WHERE wallet_address = ?
            ORDER BY detected_at DESC LIMIT ? OFFSET ?
            """,
            (wallet_address, limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
        results = self._rows_to_dicts(rows)
        for r in results:
            r["details"] = self._load_json(r.get("details"))
        return results

    async def count_by_investigation(
        self, investigation_id: str, *, severity: str | None = None
    ) -> int:
        """Count evidence items for an investigation."""
        if severity:
            async with self._conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE investigation_id = ? AND severity = ?",
                (investigation_id, severity),
            ) as cursor:
                row = await cursor.fetchone()
        else:
            async with self._conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE investigation_id = ?",
                (investigation_id,),
            ) as cursor:
                row = await cursor.fetchone()
        return row[0] if row else 0
