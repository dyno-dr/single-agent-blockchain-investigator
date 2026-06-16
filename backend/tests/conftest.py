"""
backend/tests/conftest.py
─────────────────────────────────────────────────────────────────────────────
Pytest fixtures shared across the entire test suite.

BUG FIX — background task execution in TestClient:
  Starlette's TestClient runs BackgroundTasks synchronously before returning
  the HTTP response. The background task _run_investigation_pipeline calls
  the real Etherscan API. In tests there is no mock for that call, so the
  HTTP request fails, mark_failed() is called, and the investigation ends
  up in FAILED state. When tests then call GET /report/{id} or GET /graph/{id}
  expecting 425 (Too Early / PENDING), they instead get 422 (FAILED branch).

  Fix: patch _run_investigation_pipeline to a no-op coroutine in the
  test_app fixture. This keeps the investigation in PENDING state, which is
  exactly what TestGetReport.test_pending_returns_425 and
  TestGetGraph.test_pending_returns_425 require.

  The patch target is 'backend.api.routers.investigation._run_investigation_pipeline'
  because that is the name looked up at call time by background_tasks.add_task().
"""

from __future__ import annotations

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.settings import Settings, get_settings
from backend.settings.base import (
    APISettings,
    AppSettings,
    CORSSettings,
    DatabaseSettings,
    EtherscanSettings,
    ForensicRulesConfig,
    GraphRendererConfig,
    InvestigationDefaults,
    LLMSettings,
    LoggingSettings,
    RateLimiterSettings,
    RiskScoringConfig,
    SessionSettings,
    TraceScoringWeights,
)


# ─────────────────────────────────────────────────────────────────────────────
# Settings fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def clear_settings_cache():
    """
    Clear the settings LRU cache at session start and after the session ends.

    This prevents a real .env file from leaking into the test suite.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def test_settings() -> Settings:
    """
    Return a fully isolated Settings instance for testing.

    Uses safe defaults with no real API keys. Constructs Settings directly
    rather than calling get_settings() so the lru_cache is never populated
    with production values during the test run.
    """
    get_settings.cache_clear()

    settings = Settings(
        secret_key="test-secret-key-not-for-production",
        app=AppSettings(
            name="Test Blockchain Investigator",
            version="0.0.0-test",
            env="development",
            debug=True,
        ),
        api=APISettings(
            host="127.0.0.1",
            port=8000,
            reload=False,
            workers=1,
            prefix="/api/v1",
            key="test-api-key",
        ),
        cors=CORSSettings(
            origins=["http://localhost:5173"],
            allow_credentials=True,
        ),
        etherscan=EtherscanSettings(
            api_key="test-etherscan-key-not-real",
            base_url="https://api.etherscan.io/api",
            timeout_seconds=10,
            max_retries=1,
            retry_backoff_base=0.1,
        ),
        rate_limiter=RateLimiterSettings(
            requests_per_second=4.5,
            burst_capacity=5,
        ),
        llm=LLMSettings(
            api_key="test-gemini-key-not-real",
            model="gemini-2.0-flash",
            max_tokens=1000,
            temperature=0.0,
        ),
        db=DatabaseSettings(
            path=":memory:",
            wal_mode=False,
            busy_timeout_ms=1000,
        ),
        investigation=InvestigationDefaults(
            DEFAULT_INVESTIGATION_DEPTH=2,
            DEFAULT_LOOKBACK_DAYS=90,
            DEFAULT_MAX_TRANSACTIONS=100,
            DEFAULT_FLAG_THRESHOLD_ETH=10.0,
            DEFAULT_MIN_TRACE_VALUE_ETH=0.05,
            DEFAULT_MAX_TRACE_NODES=50,
            DEFAULT_MAX_FAN_OUT_PER_NODE=10,
            MAX_TRANSACTIONS_HARD_CAP=200,
        ),
        trace_scoring=TraceScoringWeights(
            value=0.30,
            recency=0.20,
            novelty=0.30,
            rule=0.20,
        ),
        risk_scoring=RiskScoringConfig(
            RISK_WEIGHT_CRITICAL=40.0,
            RISK_WEIGHT_HIGH=20.0,
            RISK_WEIGHT_MEDIUM=10.0,
            RISK_WEIGHT_LOW=5.0,
            RISK_THRESHOLD_CRITICAL=80.0,
            RISK_THRESHOLD_HIGH=50.0,
            RISK_THRESHOLD_MEDIUM=25.0,
        ),
        forensic_rules=ForensicRulesConfig(),
        session=SessionSettings(),
        graph_renderer=GraphRendererConfig(),
        logging=LoggingSettings(
            level="DEBUG",
            format="console",
            file="",
        ),
    )
    return settings


# ─────────────────────────────────────────────────────────────────────────────
# Application client fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def test_app(test_settings: Settings):
    """
    Return a FastAPI application instance with test settings fully injected
    and the background investigation pipeline disabled.

    Patches applied:
      1. app.dependency_overrides[get_app_settings]
         → returns test_settings for all route handler DI injections.
      2. backend.persistence.database.get_settings
         → returns test_settings so init_db() opens :memory: not the disk DB.
      3. backend.api.middleware.get_settings
         → returns test_settings for CORS origin configuration.
      4. backend.api.routers.investigation._run_investigation_pipeline
         → no-op AsyncMock so BackgroundTasks never calls the real Etherscan
           API. Without this patch, TestClient runs the background task
           synchronously before returning the POST /investigate response.
           The real Etherscan call fails (test key is not valid), mark_failed()
           is called, and the investigation ends up FAILED instead of PENDING.
           Tests that check 425 Too Early then receive 422 (FAILED branch)
           instead. Patching to a no-op keeps the investigation in PENDING.
    """
    from backend.dependencies import get_app_settings
    from backend.main import app

    app.dependency_overrides[get_app_settings] = lambda: test_settings

    # _noop_pipeline is an async no-op — accepts any kwargs, does nothing.
    # This replaces the real _run_investigation_pipeline which would try
    # to open an Etherscan HTTP connection during tests.
    async def _noop_pipeline(**kwargs):
        pass

    with (
        patch("backend.persistence.database.get_settings", return_value=test_settings),
        patch("backend.api.middleware.get_settings", return_value=test_settings),
        patch(
            "backend.api.routers.investigation._run_investigation_pipeline",
            new=_noop_pipeline,
        ),
    ):
        yield app

    app.dependency_overrides.clear()


@pytest.fixture
def client(test_app) -> Generator[TestClient, None, None]:
    """
    Return a synchronous TestClient for HTTP endpoint testing.

    The lifespan context manager (startup/shutdown) is triggered by the
    TestClient context manager, so database initialisation runs exactly
    as in production — but against the in-memory test database.
    """
    with TestClient(test_app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def authed_client(client: TestClient) -> Generator[TestClient, None, None]:
    """
    Return a TestClient with the X-API-Key header pre-set.

    Use for testing routes that require authentication.
    """
    client.headers.update({"X-API-Key": "test-api-key"})
    yield client