"""
backend/tests/unit/test_persistence.py
─────────────────────────────────────────────────────────────────────────────
Unit tests for the persistence layer.

Tests:
  - DatabaseSettings and database_url resolution
  - BaseRepository helper methods (_row_to_dict, _dump_json, _load_json,
    _utc_now)
  - InvestigationRepository: create, get, list, update, mark_failed, delete
  - EvidenceRepository: create, create_batch, list, count, delete
  - ReportRepository: create, get_by_investigation, list, duplicate guard,
    update_graph_data, delete
  - Cross-repository integration: CASCADE DELETE on investigations

All tests use an in-memory SQLite database that is initialised fresh for each
test function — isolation is guaranteed.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import uuid

import aiosqlite
import pytest
import pytest_asyncio

# ─────────────────────────────────────────────────────────────────────────────
# Async test infrastructure
# ─────────────────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.asyncio


async def _open_test_db() -> aiosqlite.Connection:
    """
    Open a fresh in-memory SQLite connection, apply PRAGMAs, and run
    migrations. Returns the ready connection.
    """
    import os
    from pathlib import Path

    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row

    # Minimal PRAGMAs for tests (no WAL — not supported on :memory:)
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA synchronous = NORMAL;")
    await conn.commit()

    # Run the schema migration
    migrations_dir = (
        Path(__file__).parent.parent.parent
        / "persistence"
        / "migrations"
    )

    # Try the project source path first; fall back to the installed package path
    if not migrations_dir.exists():
        # Running from the uploaded project structure
        migrations_dir = Path(__file__).resolve()
        # Walk up to find backend/persistence/migrations
        for _ in range(6):
            migrations_dir = migrations_dir.parent
            candidate = migrations_dir / "backend" / "persistence" / "migrations"
            if candidate.exists():
                migrations_dir = candidate
                break

    sql_files = sorted(
        f for f in migrations_dir.iterdir()
        if f.suffix == ".sql" and not f.name.startswith("_")
    ) if migrations_dir.exists() else []

    for sql_file in sql_files:
        sql = sql_file.read_text(encoding="utf-8")
        await conn.executescript(sql)

    await conn.commit()
    return conn


@pytest_asyncio.fixture
async def db_conn() -> AsyncIterator[aiosqlite.Connection]:
    """Provide a fresh in-memory SQLite connection for each test."""
    conn = await _open_test_db()
    yield conn
    await conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Helper: sample wallet address
# ─────────────────────────────────────────────────────────────────────────────

WALLET = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
TX_HASH = "0x" + "a" * 64


# ─────────────────────────────────────────────────────────────────────────────
# BaseRepository helper tests
# ─────────────────────────────────────────────────────────────────────────────


class TestBaseRepository:
    async def test_utc_now_is_iso_string(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        ts = repo._utc_now()
        assert isinstance(ts, str)
        assert "+00:00" in ts or "Z" in ts or ts.endswith("+00:00")

    async def test_dump_json_none_returns_none(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        assert repo._dump_json(None) is None

    async def test_dump_json_dict(self, db_conn):
        import json

        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        result = repo._dump_json({"key": "value"})
        assert result is not None
        parsed = json.loads(result)
        assert parsed == {"key": "value"}

    async def test_load_json_none_returns_none(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        assert repo._load_json(None) is None

    async def test_load_json_empty_string_returns_none(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        assert repo._load_json("") is None

    async def test_load_json_valid(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        result = repo._load_json('{"key": "value"}')
        assert result == {"key": "value"}

    async def test_load_json_invalid_returns_none(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        assert repo._load_json("not-json{{{") is None

    async def test_dump_load_roundtrip(self, db_conn):
        from backend.persistence.repositories.base import BaseRepository

        repo = BaseRepository(db_conn)
        original = {"rule": "RULE-001", "count": 3, "nested": [1, 2, 3]}
        assert repo._load_json(repo._dump_json(original)) == original


# ─────────────────────────────────────────────────────────────────────────────
# InvestigationRepository tests
# ─────────────────────────────────────────────────────────────────────────────


class TestInvestigationRepository:
    async def test_create_returns_pending_investigation(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)

        assert inv["wallet_address"] == WALLET
        assert inv["status"] == "PENDING"
        assert inv["depth"] == 2
        assert inv["lookback_days"] == 90
        assert inv["chain"] == "ETHEREUM"
        assert inv["id"] is not None
        assert inv["created_at"] is not None
        assert inv["started_at"] is None
        assert inv["completed_at"] is None

    async def test_create_with_custom_params(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(
            wallet_address=WALLET,
            depth=3,
            lookback_days=30,
            max_transactions=200,
            chain="ETHEREUM",
            request_id="req-abc",
        )

        assert inv["depth"] == 3
        assert inv["lookback_days"] == 30
        assert inv["max_transactions"] == 200
        assert inv["request_id"] == "req-abc"

    async def test_get_existing(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        created = await repo.create(wallet_address=WALLET)
        fetched = await repo.get(created["id"])

        assert fetched is not None
        assert fetched["id"] == created["id"]

    async def test_get_nonexistent_returns_none(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        result = await repo.get(str(uuid.uuid4()))
        assert result is None

    async def test_update_status_to_running(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        updated = await repo.update_status(inv["id"], status="RUNNING", phase="PROFILER")

        assert updated is not None
        assert updated["status"] == "RUNNING"
        assert updated["phase"] == "PROFILER"
        assert updated["started_at"] is not None

    async def test_update_status_to_complete(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        await repo.update_status(inv["id"], status="RUNNING")
        updated = await repo.update_status(inv["id"], status="COMPLETE")

        assert updated is not None
        assert updated["status"] == "COMPLETE"
        assert updated["completed_at"] is not None

    async def test_update_risk(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        updated = await repo.update_risk(
            inv["id"], risk_score=72.5, risk_level="HIGH"
        )

        assert updated is not None
        assert updated["risk_score"] == "72.5"
        assert updated["risk_level"] == "HIGH"

    async def test_save_reasoning(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        log = [{"action": "TOOL_CALL", "tool": "wallet_profiler"}]
        updated = await repo.save_reasoning(inv["id"], log)

        assert updated is not None
        assert updated["reasoning_log"] == log  # deserialised

    async def test_mark_failed(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        updated = await repo.mark_failed(
            inv["id"],
            error_message="Etherscan unreachable",
            error_code="ETHERSCAN_UNREACHABLE",
            phase="PROFILER",
        )

        assert updated is not None
        assert updated["status"] == "FAILED"
        assert updated["error_message"] == "Etherscan unreachable"
        assert updated["error_code"] == "ETHERSCAN_UNREACHABLE"
        assert updated["completed_at"] is not None

    async def test_list_by_wallet(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        await repo.create(wallet_address=WALLET)
        await repo.create(wallet_address=WALLET)
        other_wallet = "0x" + "b" * 40
        await repo.create(wallet_address=other_wallet)

        results = await repo.list_by_wallet(WALLET)
        assert len(results) == 2
        assert all(r["wallet_address"] == WALLET for r in results)

    async def test_list_by_wallet_with_status_filter(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        await repo.update_status(inv["id"], status="COMPLETE")
        await repo.create(wallet_address=WALLET)  # stays PENDING

        complete = await repo.list_by_wallet(WALLET, status="COMPLETE")
        assert len(complete) == 1
        assert complete[0]["status"] == "COMPLETE"

    async def test_list_recent(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        for _ in range(5):
            await repo.create(wallet_address=WALLET)

        results = await repo.list_recent(limit=3)
        assert len(results) == 3

    async def test_count(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        initial = await repo.count()
        await repo.create(wallet_address=WALLET)
        await repo.create(wallet_address=WALLET)
        assert await repo.count() == initial + 2

    async def test_count_with_status_filter(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        await repo.update_status(inv["id"], status="COMPLETE")
        await repo.create(wallet_address=WALLET)  # stays PENDING

        assert await repo.count(status="COMPLETE") == 1
        assert await repo.count(status="PENDING") >= 1

    async def test_delete_returns_true(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        result = await repo.delete(inv["id"])
        assert result is True
        assert await repo.get(inv["id"]) is None

    async def test_delete_nonexistent_returns_false(self, db_conn):
        from backend.persistence.repositories import InvestigationRepository

        repo = InvestigationRepository(db_conn)
        result = await repo.delete(str(uuid.uuid4()))
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# EvidenceRepository tests
# ─────────────────────────────────────────────────────────────────────────────


class TestEvidenceRepository:
    async def _make_investigation(self, db_conn) -> str:
        from backend.persistence.repositories import InvestigationRepository
        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        return inv["id"]

    async def test_create_evidence(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        ev = await repo.create(
            investigation_id=inv_id,
            rule_id="RULE-001",
            rule_name="Large Transfer",
            severity="HIGH",
            description="Transfer of 15 ETH detected",
            wallet_address=WALLET,
        )

        assert ev["investigation_id"] == inv_id
        assert ev["rule_id"] == "RULE-001"
        assert ev["severity"] == "HIGH"
        assert ev["details"] is None  # no details provided
        assert ev["detected_at"] is not None

    async def test_create_evidence_with_details(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        details = {"value_eth": 15.0, "threshold_eth": 10.0}
        ev = await repo.create(
            investigation_id=inv_id,
            rule_id="RULE-001",
            rule_name="Large Transfer",
            severity="HIGH",
            description="Transfer of 15 ETH",
            wallet_address=WALLET,
            details=details,
            tx_hash=TX_HASH,
            block_number=18_000_000,
            value_eth="15.0",
        )

        assert ev["details"] == details  # deserialised
        assert ev["tx_hash"] == TX_HASH
        assert ev["block_number"] == 18_000_000
        assert ev["value_eth"] == "15.0"

    async def test_get_evidence(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)
        created = await repo.create(
            investigation_id=inv_id,
            rule_id="RULE-002",
            rule_name="Rapid Transfer",
            severity="MEDIUM",
            description="5 rapid transfers",
            wallet_address=WALLET,
        )

        fetched = await repo.get(created["id"])
        assert fetched is not None
        assert fetched["id"] == created["id"]

    async def test_get_nonexistent_returns_none(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        repo = EvidenceRepository(db_conn)
        assert await repo.get(str(uuid.uuid4())) is None

    async def test_create_batch(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        items = [
            {
                "investigation_id": inv_id,
                "rule_id": "RULE-001",
                "rule_name": "Large Transfer",
                "severity": "HIGH",
                "description": "Transfer A",
                "wallet_address": WALLET,
            },
            {
                "investigation_id": inv_id,
                "rule_id": "RULE-006",
                "rule_name": "Round Numbers",
                "severity": "LOW",
                "description": "Round amount transfer",
                "wallet_address": WALLET,
                "details": {"amount": 10.0},
            },
        ]

        results = await repo.create_batch(items)
        assert len(results) == 2
        rule_ids = {r["rule_id"] for r in results}
        assert rule_ids == {"RULE-001", "RULE-006"}

    async def test_create_batch_empty_returns_empty(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        repo = EvidenceRepository(db_conn)
        results = await repo.create_batch([])
        assert results == []

    async def test_list_by_investigation_severity_order(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        items = [
            {"investigation_id": inv_id, "rule_id": "RULE-006",
             "rule_name": "Round", "severity": "LOW",
             "description": "low", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "Large", "severity": "CRITICAL",
             "description": "critical", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-002",
             "rule_name": "Rapid", "severity": "HIGH",
             "description": "high", "wallet_address": WALLET},
        ]
        await repo.create_batch(items)

        results = await repo.list_by_investigation(inv_id)
        severities = [r["severity"] for r in results]
        # CRITICAL must appear before HIGH, HIGH before LOW
        assert severities.index("CRITICAL") < severities.index("HIGH")
        assert severities.index("HIGH") < severities.index("LOW")

    async def test_list_by_rule(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        items = [
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "Large", "severity": "HIGH",
             "description": "d", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "Large", "severity": "MEDIUM",
             "description": "d2", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-002",
             "rule_name": "Rapid", "severity": "LOW",
             "description": "d3", "wallet_address": WALLET},
        ]
        await repo.create_batch(items)

        rule_001_items = await repo.list_by_rule("RULE-001")
        assert len(rule_001_items) == 2
        assert all(r["rule_id"] == "RULE-001" for r in rule_001_items)

    async def test_list_by_wallet(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        other_wallet = "0x" + "c" * 40
        items = [
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "Large", "severity": "HIGH",
             "description": "d", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "Large", "severity": "MEDIUM",
             "description": "d2", "wallet_address": other_wallet},
        ]
        await repo.create_batch(items)

        results = await repo.list_by_wallet(WALLET)
        assert len(results) == 1
        assert results[0]["wallet_address"] == WALLET

    async def test_count_by_investigation(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        items = [
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "Large", "severity": "HIGH",
             "description": "d", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-002",
             "rule_name": "Rapid", "severity": "LOW",
             "description": "d2", "wallet_address": WALLET},
        ]
        await repo.create_batch(items)

        total = await repo.count_by_investigation(inv_id)
        assert total == 2

        high = await repo.count_by_investigation(inv_id, severity="HIGH")
        assert high == 1

    async def test_delete_by_investigation(self, db_conn):
        from backend.persistence.repositories import EvidenceRepository

        inv_id = await self._make_investigation(db_conn)
        repo = EvidenceRepository(db_conn)

        items = [
            {"investigation_id": inv_id, "rule_id": "RULE-001",
             "rule_name": "L", "severity": "HIGH",
             "description": "d", "wallet_address": WALLET},
            {"investigation_id": inv_id, "rule_id": "RULE-002",
             "rule_name": "R", "severity": "LOW",
             "description": "d2", "wallet_address": WALLET},
        ]
        await repo.create_batch(items)

        deleted = await repo.delete_by_investigation(inv_id)
        assert deleted == 2
        remaining = await repo.list_by_investigation(inv_id)
        assert remaining == []


# ─────────────────────────────────────────────────────────────────────────────
# ReportRepository tests
# ─────────────────────────────────────────────────────────────────────────────


class TestReportRepository:
    async def _make_investigation(self, db_conn) -> str:
        from backend.persistence.repositories import InvestigationRepository
        repo = InvestigationRepository(db_conn)
        inv = await repo.create(wallet_address=WALLET)
        # Mark complete so the report makes semantic sense
        await repo.update_status(inv["id"], status="COMPLETE")
        return inv["id"]

    def _sample_report_kwargs(self, inv_id: str) -> dict:
        return {
            "investigation_id": inv_id,
            "title": "Investigation Report: " + WALLET[:10],
            "summary": "The wallet exhibits suspicious activity patterns.",
            "findings": [
                {"rule_id": "RULE-001", "severity": "HIGH",
                 "description": "Large transfer detected"}
            ],
            "risk_score": 72.5,
            "risk_level": "HIGH",
            "evidence_count": 3,
            "recommendations": ["Monitor wallet", "Report to exchange"],
            "model_used": "claude-sonnet-4-20250514",
        }

    async def test_create_report(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        report = await repo.create(**self._sample_report_kwargs(inv_id))

        assert report["investigation_id"] == inv_id
        assert report["risk_level"] == "HIGH"
        assert report["risk_score"] == "72.5"
        assert report["evidence_count"] == 3
        assert report["generated_at"] is not None
        # JSON fields deserialised
        assert isinstance(report["findings_json"], list)
        assert len(report["findings_json"]) == 1
        assert isinstance(report["recommendations_json"], list)
        assert report["graph_data"] is None

    async def test_get_report(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        created = await repo.create(**self._sample_report_kwargs(inv_id))
        fetched = await repo.get(created["id"])

        assert fetched is not None
        assert fetched["id"] == created["id"]

    async def test_get_nonexistent_returns_none(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        repo = ReportRepository(db_conn)
        assert await repo.get(str(uuid.uuid4())) is None

    async def test_get_by_investigation(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        created = await repo.create(**self._sample_report_kwargs(inv_id))

        fetched = await repo.get_by_investigation(inv_id)
        assert fetched is not None
        assert fetched["id"] == created["id"]

    async def test_get_by_investigation_no_report_returns_none(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        assert await repo.get_by_investigation(inv_id) is None

    async def test_duplicate_create_raises_repository_exception(self, db_conn):
        from backend.exceptions import RepositoryException
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        await repo.create(**self._sample_report_kwargs(inv_id))

        with pytest.raises(RepositoryException, match="already exists"):
            await repo.create(**self._sample_report_kwargs(inv_id))

    async def test_update_graph_data(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        created = await repo.create(**self._sample_report_kwargs(inv_id))

        graph = {"nodes": [{"id": WALLET}], "edges": []}
        updated = await repo.update_graph_data(created["id"], graph)

        assert updated is not None
        assert updated["graph_data"] == graph  # deserialised

    async def test_update_graph_data_nonexistent_returns_none(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        repo = ReportRepository(db_conn)
        result = await repo.update_graph_data(str(uuid.uuid4()), {"nodes": []})
        assert result is None

    async def test_list_recent(self, db_conn):
        from backend.persistence.repositories import (
            InvestigationRepository,
            ReportRepository,
        )

        inv_repo = InvestigationRepository(db_conn)
        report_repo = ReportRepository(db_conn)

        for _ in range(3):
            inv = await inv_repo.create(wallet_address=WALLET)
            await inv_repo.update_status(inv["id"], status="COMPLETE")
            await report_repo.create(
                investigation_id=inv["id"],
                title="Report",
                summary="Summary",
                findings=[],
                risk_score=50.0,
                risk_level="MEDIUM",
                evidence_count=0,
            )

        reports = await report_repo.list_recent(limit=2)
        assert len(reports) == 2

    async def test_list_by_risk_level(self, db_conn):
        from backend.persistence.repositories import (
            InvestigationRepository,
            ReportRepository,
        )

        inv_repo = InvestigationRepository(db_conn)
        report_repo = ReportRepository(db_conn)

        inv_high = await inv_repo.create(wallet_address=WALLET)
        await inv_repo.update_status(inv_high["id"], status="COMPLETE")
        await report_repo.create(
            investigation_id=inv_high["id"],
            title="High Report",
            summary="s",
            findings=[],
            risk_score=75.0,
            risk_level="HIGH",
            evidence_count=1,
        )

        other_wallet = "0x" + "d" * 40
        inv_low = await inv_repo.create(wallet_address=other_wallet)
        await inv_repo.update_status(inv_low["id"], status="COMPLETE")
        await report_repo.create(
            investigation_id=inv_low["id"],
            title="Low Report",
            summary="s",
            findings=[],
            risk_score=15.0,
            risk_level="LOW",
            evidence_count=0,
        )

        high_reports = await report_repo.list_by_risk_level("HIGH")
        assert len(high_reports) >= 1
        assert all(r["risk_level"] == "HIGH" for r in high_reports)

    async def test_exists_for_investigation(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)

        assert not await repo.exists_for_investigation(inv_id)
        await repo.create(**self._sample_report_kwargs(inv_id))
        assert await repo.exists_for_investigation(inv_id)

    async def test_count(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)

        initial = await repo.count()
        await repo.create(**self._sample_report_kwargs(inv_id))
        assert await repo.count() == initial + 1

    async def test_delete(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        inv_id = await self._make_investigation(db_conn)
        repo = ReportRepository(db_conn)
        created = await repo.create(**self._sample_report_kwargs(inv_id))

        assert await repo.delete(created["id"]) is True
        assert await repo.get(created["id"]) is None

    async def test_delete_nonexistent_returns_false(self, db_conn):
        from backend.persistence.repositories import ReportRepository

        repo = ReportRepository(db_conn)
        assert await repo.delete(str(uuid.uuid4())) is False


# ─────────────────────────────────────────────────────────────────────────────
# Cross-repository: CASCADE DELETE
# ─────────────────────────────────────────────────────────────────────────────


class TestCascadeDelete:
    async def test_deleting_investigation_cascades_to_evidence(self, db_conn):
        from backend.persistence.repositories import (
            EvidenceRepository,
            InvestigationRepository,
        )

        inv_repo = InvestigationRepository(db_conn)
        ev_repo = EvidenceRepository(db_conn)

        inv = await inv_repo.create(wallet_address=WALLET)
        ev = await ev_repo.create(
            investigation_id=inv["id"],
            rule_id="RULE-001",
            rule_name="Large Transfer",
            severity="HIGH",
            description="test",
            wallet_address=WALLET,
        )

        ev_id = ev["id"]
        await inv_repo.delete(inv["id"])

        assert await ev_repo.get(ev_id) is None

    async def test_deleting_investigation_cascades_to_report(self, db_conn):
        from backend.persistence.repositories import (
            InvestigationRepository,
            ReportRepository,
        )

        inv_repo = InvestigationRepository(db_conn)
        report_repo = ReportRepository(db_conn)

        inv = await inv_repo.create(wallet_address=WALLET)
        await inv_repo.update_status(inv["id"], status="COMPLETE")
        report = await report_repo.create(
            investigation_id=inv["id"],
            title="Report",
            summary="s",
            findings=[],
            risk_score=50.0,
            risk_level="MEDIUM",
            evidence_count=0,
        )

        report_id = report["id"]
        await inv_repo.delete(inv["id"])

        assert await report_repo.get(report_id) is None
