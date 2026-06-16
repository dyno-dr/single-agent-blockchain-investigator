"""
backend/tests/unit/test_foundation.py
─────────────────────────────────────────────────────────────────────────────
Unit tests for the project foundation layer.

Tests:
  - Settings construction and validation
  - Utility functions (address validation, type conversions, pagination)
  - Constants integrity
  - Health and version endpoints
  - Dependency injection (API key auth)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Settings tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSettings:
    def test_settings_loads(self, test_settings):
        assert test_settings.app.version == "0.0.0-test"
        assert test_settings.app.env == "development"
        assert test_settings.app.debug is True

    def test_trace_weights_sum_to_one(self, test_settings):
        w = test_settings.trace_scoring
        total = w.value + w.recency + w.novelty + w.rule
        assert abs(total - 1.0) < 0.001

    def test_trace_weights_invalid_raises(self):
        from pydantic import ValidationError
        from backend.settings.base import TraceScoringWeights

        with pytest.raises(ValidationError, match="must sum to 1.0"):
            TraceScoringWeights(value=0.5, recency=0.5, novelty=0.5, rule=0.5)

    def test_cors_origins_from_comma_string(self):
        from backend.settings.base import CORSSettings

        s = CORSSettings(origins="http://localhost:3000,http://localhost:5173")
        assert "http://localhost:3000" in s.origins
        assert "http://localhost:5173" in s.origins

    def test_cors_origins_from_json_string(self):
        from backend.settings.base import CORSSettings

        s = CORSSettings(origins='["http://localhost:3000"]')
        assert s.origins == ["http://localhost:3000"]

    def test_is_development_property(self, test_settings):
        assert test_settings.is_development is True
        assert test_settings.is_production is False

    def test_database_url_resolves_relative_path(self, test_settings):
        # :memory: is a special SQLite path; test with a relative path instead
        from backend.settings.base import DatabaseSettings, Settings
        import os

        s = Settings(
            db=DatabaseSettings(path="data/test.db"),
            app=test_settings.app,
        )
        # Path must be absolute (works on both Windows and Unix)
        assert os.path.isabs(s.database_url)
        # Path must end with the configured filename
        assert s.database_url.endswith("test.db")
        # Must not be the raw relative string
        assert s.database_url != "data/test.db"

    def test_api_key_not_in_repr(self, test_settings):
        # Secrets must not appear in repr (repr=False)
        rep = repr(test_settings.api)
        assert "test-api-key" not in rep

    def test_etherscan_key_not_in_repr(self, test_settings):
        rep = repr(test_settings.etherscan)
        assert "test-etherscan-key" not in rep


# ─────────────────────────────────────────────────────────────────────────────
# Utils tests
# ─────────────────────────────────────────────────────────────────────────────


class TestUtils:
    def test_is_valid_eth_address_valid(self):
        from backend.utils import is_valid_eth_address

        assert is_valid_eth_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
        assert is_valid_eth_address("0x" + "a" * 40)
        assert is_valid_eth_address("0x" + "0" * 40)

    def test_is_valid_eth_address_invalid(self):
        from backend.utils import is_valid_eth_address

        assert not is_valid_eth_address("not_an_address")
        assert not is_valid_eth_address("0x" + "g" * 40)   # invalid hex char
        assert not is_valid_eth_address("0x" + "a" * 39)   # too short
        assert not is_valid_eth_address("0x" + "a" * 41)   # too long
        assert not is_valid_eth_address("")
        assert not is_valid_eth_address(None)  # type: ignore[arg-type]

    def test_is_valid_tx_hash_valid(self):
        from backend.utils import is_valid_tx_hash

        assert is_valid_tx_hash("0x" + "a" * 64)

    def test_is_valid_tx_hash_invalid(self):
        from backend.utils import is_valid_tx_hash

        assert not is_valid_tx_hash("0x" + "a" * 63)
        assert not is_valid_tx_hash("0x" + "a" * 65)
        assert not is_valid_tx_hash("")

    def test_normalize_address(self):
        from backend.utils import normalize_address

        addr = "0xD8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        assert normalize_address(addr) == addr.lower()

    def test_normalize_address_invalid_raises(self):
        from backend.utils import normalize_address

        with pytest.raises(ValueError, match="Invalid Ethereum address"):
            normalize_address("not_an_address")

    def test_wei_to_eth(self):
        from backend.utils import wei_to_eth

        assert wei_to_eth(1_000_000_000_000_000_000) == 1.0
        assert wei_to_eth(500_000_000_000_000_000) == 0.5

    def test_eth_to_wei(self):
        from backend.utils import eth_to_wei

        assert eth_to_wei(1.0) == 1_000_000_000_000_000_000
        assert eth_to_wei(0.5) == 500_000_000_000_000_000

    def test_wei_eth_roundtrip(self):
        from backend.utils import eth_to_wei, wei_to_eth

        original = 3.14159
        assert abs(wei_to_eth(eth_to_wei(original)) - original) < 1e-9

    def test_clamp(self):
        from backend.utils import clamp

        assert clamp(5.0, 0.0, 10.0) == 5.0
        assert clamp(-1.0, 0.0, 10.0) == 0.0
        assert clamp(11.0, 0.0, 10.0) == 10.0

    def test_safe_divide(self):
        from backend.utils import safe_divide

        assert safe_divide(10.0, 2.0) == 5.0
        assert safe_divide(10.0, 0.0) == 0.0
        assert safe_divide(10.0, 0.0, default=-1.0) == -1.0

    def test_truncate(self):
        from backend.utils import truncate

        assert truncate("hello", 10) == "hello"
        assert truncate("hello world", 8) == "hello..."
        assert len(truncate("x" * 100, 20)) == 20

    def test_mask_api_key(self):
        from backend.utils import mask_api_key

        masked = mask_api_key("abcdefghijklmnop")
        assert masked.startswith("abcd")
        assert masked.endswith("mnop")
        assert "****" in masked

        short = mask_api_key("abc")
        assert short == "****"

    def test_calculate_offset(self):
        from backend.utils import calculate_offset

        assert calculate_offset(1, 20) == 0
        assert calculate_offset(2, 20) == 20
        assert calculate_offset(3, 20) == 40

    def test_paginate_list(self):
        from backend.utils import paginate_list

        items = list(range(100))
        page = paginate_list(items, limit=10, offset=20)
        assert page == list(range(20, 30))

    def test_generate_session_id_is_uuid(self):
        import uuid
        from backend.utils import generate_session_id

        sid = generate_session_id()
        # Should parse as a valid UUID without raising
        uuid.UUID(sid)

    def test_utc_now_is_aware(self):
        from backend.utils import utc_now

        dt = utc_now()
        assert dt.tzinfo is not None

    def test_unix_to_utc(self):
        from backend.utils import unix_to_utc

        dt = unix_to_utc(0)
        assert dt.year == 1970

    def test_short_hash_length(self):
        from backend.utils import short_hash

        h = short_hash("test_value")
        assert len(h) == 12
        # Same input → same output (deterministic)
        assert short_hash("test_value") == short_hash("test_value")
        # Different input → different output
        assert short_hash("a") != short_hash("b")


# ─────────────────────────────────────────────────────────────────────────────
# Constants tests
# ─────────────────────────────────────────────────────────────────────────────


class TestConstants:
    def test_all_rule_ids_tuple(self):
        from backend.constants import ALL_RULE_IDS

        assert len(ALL_RULE_IDS) == 7
        assert all(rid.startswith("RULE-") for rid in ALL_RULE_IDS)

    def test_investigation_status_values(self):
        from backend.constants import InvestigationStatus

        assert InvestigationStatus.PENDING == "PENDING"
        assert InvestigationStatus.RUNNING == "RUNNING"
        assert InvestigationStatus.COMPLETE == "COMPLETE"
        assert InvestigationStatus.FAILED == "FAILED"

    def test_risk_level_ordering(self):
        from backend.constants import RiskLevel

        levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert all(isinstance(l, str) for l in levels)

    def test_ws_event_type_str_values(self):
        from backend.constants import WsEventType

        # StrEnum: value == name used in JSON
        assert WsEventType.COMPLETE == "COMPLETE"
        assert WsEventType.PHASE_START == "PHASE_START"

    def test_graph_renderer_mode(self):
        from backend.constants import GraphRendererMode

        assert GraphRendererMode.SVG == "svg"
        assert GraphRendererMode.CANVAS == "canvas"
        assert GraphRendererMode.WEBGL == "webgl"


# ─────────────────────────────────────────────────────────────────────────────
# Health endpoint tests
# ─────────────────────────────────────────────────────────────────────────────


class TestHealthEndpoint:
    def test_health_returns_200(self, client: TestClient):
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_response_shape(self, client: TestClient):
        data = client.get("/api/v1/health").json()
        assert "status" in data
        assert "version" in data
        assert "timestamp" in data
        assert "uptime_seconds" in data
        assert "checks" in data

    def test_health_status_ok(self, client: TestClient):
        data = client.get("/api/v1/health").json()
        assert data["status"] in ("ok", "degraded")  # degraded OK in test env

    def test_health_no_auth_required(self, client: TestClient):
        # Health must be accessible without X-API-Key
        response = client.get("/api/v1/health")
        assert response.status_code != 401

    def test_health_includes_request_id_header(self, client: TestClient):
        response = client.get("/api/v1/health")
        assert "x-request-id" in response.headers

    def test_health_includes_process_time_header(self, client: TestClient):
        response = client.get("/api/v1/health")
        assert "x-process-time-ms" in response.headers


class TestVersionEndpoint:
    def test_version_returns_200(self, client: TestClient):
        response = client.get("/api/v1/version")
        assert response.status_code == 200

    def test_version_response_shape(self, client: TestClient):
        data = client.get("/api/v1/version").json()
        assert "version" in data
        assert "agent_version" in data
        assert "environment" in data
        assert "python_version" in data

    def test_version_no_auth_required(self, client: TestClient):
        response = client.get("/api/v1/version")
        assert response.status_code != 401


# ─────────────────────────────────────────────────────────────────────────────
# API key authentication tests
# ─────────────────────────────────────────────────────────────────────────────


class TestApiKeyAuth:
    def test_verify_api_key_valid(self, test_settings):
        """verify_api_key passes when header matches settings."""
        import asyncio
        from backend.dependencies import verify_api_key

        # FIX: asyncio.get_event_loop().run_until_complete() is deprecated in
        # Python 3.10+ and raises DeprecationWarning / errors in 3.12+.
        # asyncio.run() creates a fresh event loop for each call — correct for
        # synchronous test functions that need to await a coroutine once.
        result = asyncio.run(
            verify_api_key(api_key="test-api-key", settings=test_settings)
        )
        assert result == "test-api-key"

    def test_verify_api_key_missing_raises_401(self, test_settings):
        """verify_api_key raises 401 when header is absent."""
        import asyncio
        from fastapi import HTTPException
        from backend.dependencies import verify_api_key

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                verify_api_key(api_key=None, settings=test_settings)
            )
        assert exc_info.value.status_code == 401

    def test_verify_api_key_wrong_value_raises_401(self, test_settings):
        """verify_api_key raises 401 when key is wrong."""
        import asyncio
        from fastapi import HTTPException
        from backend.dependencies import verify_api_key

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                verify_api_key(api_key="wrong-key", settings=test_settings)
            )
        assert exc_info.value.status_code == 401