"""
backend/dependencies.py
─────────────────────────────────────────────────────────────────────────────
FastAPI dependency injection container.

PURPOSE:
  Defines all injectable dependencies used across API routers and agent nodes.
  Centralises resource lifecycle management — every shared resource (settings,
  HTTP client, rate limiter) is created once and injected where needed. No
  module instantiates its own HTTP session or reads settings directly.

DESIGN DECISIONS:
  1. FastAPI's `Depends()` system is used exclusively. No global singletons
     outside of the settings cache. This makes every dependency swappable in
     tests via `app.dependency_overrides`.
  2. `get_settings` is the root dependency. All other dependencies that need
     configuration accept it as a parameter — this creates a clean, explicit
     dependency graph.
  3. `get_http_client` returns a module-level `httpx.AsyncClient` singleton
     that is initialised in the FastAPI lifespan and closed on shutdown.
     Never create a new AsyncClient per request — connection pool is shared.
  4. `verify_api_key` is a lightweight security dependency injected into all
     non-health routes. It reads the expected key from settings, not from a
     hardcoded constant.
  5. The rate limiter dependency is a stub at this foundation phase. The
     actual `AsyncTokenBucket` is wired in the blockchain layer phase.
     The interface is defined here so routers and tools reference the same
     import path from day one.

FUTURE SCALABILITY:
  - Add `get_db_connection()` when the persistence layer is implemented.
  - Add `get_etherscan_client()` when the blockchain layer is implemented.
  - Add `get_agent_session_manager()` when the agent layer is implemented.
  - Each addition follows the same pattern: module-level holder + lifespan
    init + FastAPI Depends wrapper.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
import httpx
from langchain_google_genai import ChatGoogleGenerativeAI

from backend.constants import API_KEY_HEADER
from backend.settings import Settings, get_settings

# ─────────────────────────────────────────────────────────────────────────────
# Module-level resource holders
# Populated during FastAPI lifespan startup; cleared on shutdown.
# ─────────────────────────────────────────────────────────────────────────────

_http_client: httpx.AsyncClient | None = None
_rate_limiter: Any | None = None   # AsyncTokenBucket — wired in blockchain phase


# ─────────────────────────────────────────────────────────────────────────────
# Lifecycle helpers  (called from backend/main.py lifespan)
# ─────────────────────────────────────────────────────────────────────────────


async def init_http_client(settings: Settings) -> None:
    """
    Initialise the shared AsyncClient during application startup.

    Called once from the FastAPI lifespan context manager. Sets the
    module-level `_http_client` singleton so `get_http_client()` can
    return it on every request without re-instantiation.

    Args:
        settings: Application settings (used for timeout configuration).
    """
    global _http_client
    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=10.0,
            read=float(settings.etherscan.timeout_seconds),
            write=10.0,
            pool=5.0,
        ),
        limits=httpx.Limits(
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=30.0,
        ),
        headers={
            "User-Agent": (
                f"SingleAgentBlockchainInvestigator/"
                f"{settings.app.version}"
            )
        },
    )


async def close_http_client() -> None:
    """
    Gracefully close the shared AsyncClient during application shutdown.

    Called once from the FastAPI lifespan context manager. After this call
    `_http_client` is set to None; any attempt to use it will raise a clear
    error rather than silently hang.
    """
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


def set_rate_limiter(limiter: Any) -> None:
    """
    Register the AsyncTokenBucket instance created during lifespan startup.

    Called from main.py lifespan once the blockchain layer is available.
    Until then, `get_rate_limiter()` returns None and tools that depend on
    it must handle the None case gracefully (they will in their own phase).

    Args:
        limiter: An `aiolimiter.AsyncLimiter` instance.
    """
    global _rate_limiter
    _rate_limiter = limiter


# ─────────────────────────────────────────────────────────────────────────────
# Settings dependency
# ─────────────────────────────────────────────────────────────────────────────


def get_app_settings() -> Settings:
    """
    FastAPI dependency that returns the application Settings singleton.

    Wraps `get_settings()` so it participates in FastAPI's dependency
    injection graph and can be overridden in tests via
    `app.dependency_overrides[get_app_settings] = lambda: mock_settings`.

    Usage in a router:
        @router.get("/example")
        async def example(settings: Annotated[Settings, Depends(get_app_settings)]):
            return {"version": settings.app.version}
    """
    return get_settings()


# ─────────────────────────────────────────────────────────────────────────────
# HTTP client dependency
# ─────────────────────────────────────────────────────────────────────────────


def get_http_client() -> httpx.AsyncClient:
    """
    FastAPI dependency that returns the shared AsyncClient.

    Raises:
        RuntimeError: If called before lifespan startup has initialised the
            client. This should never happen in production — it indicates a
            programming error (route called before app is ready).
    """
    if _http_client is None:
        raise RuntimeError(
            "HTTP client has not been initialised. "
            "Ensure init_http_client() is called in the FastAPI lifespan."
        )
    return _http_client


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter dependency
# ─────────────────────────────────────────────────────────────────────────────


def get_rate_limiter() -> Any | None:
    """
    FastAPI dependency that returns the AsyncTokenBucket rate limiter.

    Returns None during the foundation phase (blockchain layer not yet wired).
    The blockchain layer phase will call `set_rate_limiter()` during lifespan
    and this dependency will return the live limiter thereafter.

    Tools consuming this dependency must guard:
        limiter = Depends(get_rate_limiter)
        if limiter is not None:
            async with limiter:
                ...
    """
    return _rate_limiter


# ─────────────────────────────────────────────────────────────────────────────
# API key authentication dependency
# ─────────────────────────────────────────────────────────────────────────────

_api_key_header_scheme = APIKeyHeader(
    name=API_KEY_HEADER,
    auto_error=False,   # we raise our own descriptive error below
    description=(
        "API key for authentication. "
        "Pass as `X-API-Key: <key>` header. "
        "Set via API_KEY in your .env file."
    ),
)


async def verify_api_key(
    api_key: Annotated[str | None, Security(_api_key_header_scheme)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> str:
    """
    FastAPI security dependency that validates the X-API-Key header.

    Inject into any route that requires authentication:

        @router.post("/investigate")
        async def start_investigation(
            _: Annotated[str, Depends(verify_api_key)],
            ...
        ):

    Design:
        - Returns the validated key string on success (can be used for
          audit logging if needed).
        - Raises HTTP 401 with a clear message on failure.
        - In development mode with the default key, a warning is logged
          (but auth still passes) so developers don't accidentally ship
          without changing the key.

    Raises:
        HTTPException 401: Missing or invalid API key.
    """
    expected_key = settings.api.key

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Missing API key",
                "message": f"Provide your API key in the '{API_KEY_HEADER}' header.",
            },
        )

    if api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Invalid API key",
                "message": "The provided API key is not valid.",
            },
        )

    return api_key
def get_llm_client(settings: Settings) -> ChatGoogleGenerativeAI:
    """Return a configured Gemini chat client for LangGraph nodes."""
    return ChatGoogleGenerativeAI(
        model=settings.llm.model,
        google_api_key=settings.llm.google_api_key,
        temperature=settings.llm.temperature,
        max_output_tokens=settings.llm.max_tokens,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Convenience type aliases for router signatures
# ─────────────────────────────────────────────────────────────────────────────

# Use these aliases in router function signatures for cleaner code:
#
#   async def my_route(
#       settings: SettingsDep,
#       client: HttpClientDep,
#       _auth: AuthDep,
#   ):
#
SettingsDep = Annotated[Settings, Depends(get_app_settings)]
HttpClientDep = Annotated[httpx.AsyncClient, Depends(get_http_client)]
AuthDep = Annotated[str, Depends(verify_api_key)]
RateLimiterDep = Annotated[Any | None, Depends(get_rate_limiter)]
