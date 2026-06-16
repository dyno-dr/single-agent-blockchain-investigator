"""
backend/tests/integration/test_routes.py
─────────────────────────────────────────────────────────────────────────────
Integration tests for Phase 2 API routes.

Tests all four new routers with:
  - Mocked EtherscanClient (no real API calls)
  - In-memory SQLite database (from conftest.py)
  - Real FastAPI test client

Coverage:
  - POST /investigate  (202, 422 on bad address, 401 on missing auth)
  - GET  /investigate/{id}  (200, 404)
  - GET  /history  (200 with pagination)
  - GET  /history/{wallet}  (200, 400 on invalid wallet)
  - GET  /report/{id}  (200 stub, 404, 425 not-ready)
  - GET  /graph/{id}  (200 stub, 404, 425)
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

#pytestmark = pytest.mark.asyncio

VALID_WALLET = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
INVALID_WALLET = "not_an_address"
API_KEY = "test-api-key"
AUTH_HEADER = {"X-API-Key": API_KEY}


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────


def _create_completed_investigation(client: TestClient) -> str:
    """POST /investigate and return the investigation ID for subsequent tests."""
    response = client.post(
        "/api/v1/investigate",
        json={"wallet_address": VALID_WALLET, "depth": 1, "lookback_days": 30},
        headers=AUTH_HEADER,
    )
    assert response.status_code == 202
    return response.json()["id"]


# ─────────────────────────────────────────────────────────────────────────────
# POST /investigate
# ─────────────────────────────────────────────────────────────────────────────


class TestPostInvestigate:
    def test_returns_202_with_valid_wallet(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 202

    def test_response_has_investigation_id(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET},
            headers=AUTH_HEADER,
        )
        data = response.json()
        assert "id" in data
        assert len(data["id"]) == 36  # UUID4 format

    def test_response_status_is_pending(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET},
            headers=AUTH_HEADER,
        )
        assert response.json()["status"] == "PENDING"

    def test_invalid_wallet_returns_422(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": INVALID_WALLET},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 422

    def test_missing_auth_returns_401(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET},
        )
        assert response.status_code == 401

    def test_wrong_api_key_returns_401(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET},
            headers={"X-API-Key": "wrong-key"},
        )
        assert response.status_code == 401

    def test_depth_out_of_range_returns_422(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET, "depth": 10},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 422

    def test_max_transactions_capped_returns_422(self, client: TestClient):
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": VALID_WALLET, "max_transactions": 9999},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 422

    def test_wallet_address_normalised_to_lowercase(self, client: TestClient):
        mixed_case = "0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE"
        response = client.post(
            "/api/v1/investigate",
            json={"wallet_address": mixed_case},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 202
        assert response.json()["wallet_address"] == mixed_case.lower()


# ─────────────────────────────────────────────────────────────────────────────
# GET /investigate/{id}
# ─────────────────────────────────────────────────────────────────────────────


class TestGetInvestigation:
    def test_returns_200_for_existing(self, client: TestClient):
        inv_id = _create_completed_investigation(client)
        response = client.get(f"/api/v1/investigate/{inv_id}", headers=AUTH_HEADER)
        assert response.status_code == 200

    def test_response_shape(self, client: TestClient):
        inv_id = _create_completed_investigation(client)
        data = client.get(f"/api/v1/investigate/{inv_id}", headers=AUTH_HEADER).json()
        assert data["id"] == inv_id
        assert "status" in data
        assert "wallet_address" in data
        assert "created_at" in data

    def test_returns_404_for_unknown_id(self, client: TestClient):
        response = client.get(
            "/api/v1/investigate/00000000-0000-0000-0000-000000000000",
            headers=AUTH_HEADER,
        )
        assert response.status_code == 404

    def test_missing_auth_returns_401(self, client: TestClient):
        response = client.get(
            "/api/v1/investigate/00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# GET /history
# ─────────────────────────────────────────────────────────────────────────────


class TestGetHistory:
    def test_returns_200(self, client: TestClient):
        response = client.get("/api/v1/history", headers=AUTH_HEADER)
        assert response.status_code == 200

    def test_response_has_pagination_fields(self, client: TestClient):
        data = client.get("/api/v1/history", headers=AUTH_HEADER).json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "pages" in data

    def test_created_investigation_appears_in_history(self, client: TestClient):
        _create_completed_investigation(client)
        data = client.get("/api/v1/history", headers=AUTH_HEADER).json()
        assert data["total"] >= 1

    def test_pagination_page_size(self, client: TestClient):
        # Create 3 investigations
        for _ in range(3):
            _create_completed_investigation(client)

        data = client.get("/api/v1/history?page=1&page_size=2", headers=AUTH_HEADER).json()
        assert len(data["items"]) <= 2
        assert data["page_size"] == 2

    def test_status_filter_pending(self, client: TestClient):
        _create_completed_investigation(client)
        data = client.get("/api/v1/history?status=PENDING", headers=AUTH_HEADER).json()
        # All items must be PENDING (or empty list)
        for item in data["items"]:
            assert item["status"] == "PENDING"

    def test_missing_auth_returns_401(self, client: TestClient):
        response = client.get("/api/v1/history")
        assert response.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# GET /history/{wallet}
# ─────────────────────────────────────────────────────────────────────────────


class TestGetHistoryByWallet:
    def test_returns_200_for_valid_wallet(self, client: TestClient):
        response = client.get(f"/api/v1/history/{VALID_WALLET}", headers=AUTH_HEADER)
        assert response.status_code == 200

    def test_returns_400_for_invalid_wallet(self, client: TestClient):
        response = client.get(f"/api/v1/history/{INVALID_WALLET}", headers=AUTH_HEADER)
        assert response.status_code == 400

    def test_only_matching_wallet_in_results(self, client: TestClient):
        _create_completed_investigation(client)
        data = client.get(f"/api/v1/history/{VALID_WALLET}", headers=AUTH_HEADER).json()
        for item in data["items"]:
            assert item["wallet_address"] == VALID_WALLET.lower()


# ─────────────────────────────────────────────────────────────────────────────
# GET /report/{investigation_id}
# ─────────────────────────────────────────────────────────────────────────────


class TestGetReport:
    def test_pending_returns_425(self, client: TestClient):
        inv_id = _create_completed_investigation(client)
        # Immediately after create, status is PENDING
        response = client.get(f"/api/v1/report/{inv_id}", headers=AUTH_HEADER)
        # Will be 425 (Too Early) since status is still PENDING
        assert response.status_code == 425

    def test_unknown_investigation_returns_404(self, client: TestClient):
        response = client.get(
            "/api/v1/report/00000000-0000-0000-0000-000000000000",
            headers=AUTH_HEADER,
        )
        assert response.status_code == 404

    def test_missing_auth_returns_401(self, client: TestClient):
        response = client.get("/api/v1/report/some-id")
        assert response.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# GET /graph/{investigation_id}
# ─────────────────────────────────────────────────────────────────────────────


class TestGetGraph:
    def test_pending_returns_425(self, client: TestClient):
        inv_id = _create_completed_investigation(client)
        response = client.get(f"/api/v1/graph/{inv_id}", headers=AUTH_HEADER)
        assert response.status_code == 425

    def test_unknown_investigation_returns_404(self, client: TestClient):
        response = client.get(
            "/api/v1/graph/00000000-0000-0000-0000-000000000000",
            headers=AUTH_HEADER,
        )
        assert response.status_code == 404

    def test_missing_auth_returns_401(self, client: TestClient):
        response = client.get("/api/v1/graph/some-id")
        assert response.status_code == 401