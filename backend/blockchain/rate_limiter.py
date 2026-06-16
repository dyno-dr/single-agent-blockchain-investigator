"""
backend/blockchain/rate_limiter.py
─────────────────────────────────────────────────────────────────────────────
Async token-bucket rate limiter wrapping aiolimiter.AsyncLimiter.

PURPOSE:
  Ensures the Etherscan HTTP client never exceeds the free-tier API rate limit
  (5 requests/second). Every outbound Etherscan call acquires a token before
  sending, transparently queuing callers when the bucket is exhausted rather
  than hard-failing them.

DESIGN DECISIONS:
  1. Wraps `aiolimiter.AsyncLimiter` — a well-tested async token bucket that
     supports both sustained rate and burst capacity.
  2. `EtherscanRateLimiter` is a thin façade. It exposes an async context
     manager (`async with limiter`) so call sites are identical whether the
     limiter is active or a no-op stub.
  3. Built from `RateLimiterSettings` so all thresholds live in .env / Settings.
  4. `create_rate_limiter()` is the factory called from `main.py` lifespan.
     `set_rate_limiter()` in `dependencies.py` registers the result for DI.
  5. `NullRateLimiter` is a test-safe no-op that satisfies the same interface
     without importing aiolimiter. Injected via dependency override in tests.

FUTURE SCALABILITY:
  - Swap in a Redis-backed distributed limiter when moving to multi-worker
    deployments (keep the same context-manager interface).
  - Add per-endpoint rate limiting by accepting an `endpoint` parameter.
"""

from __future__ import annotations

from aiolimiter import AsyncLimiter
import structlog

from backend.settings import Settings

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Core rate limiter
# ─────────────────────────────────────────────────────────────────────────────


class EtherscanRateLimiter:
    """
    Async token-bucket rate limiter for the Etherscan API client.

    Usage:
        async with rate_limiter:
            response = await http_client.get(url)

    The context manager blocks until a token is available, then releases it
    automatically on exit. Concurrent callers queue transparently.

    Args:
        requests_per_second: Sustained request rate (default 4.5 — 10% below
            Etherscan free tier to absorb clock skew).
        burst_capacity: Maximum tokens that can accumulate (default 5).
    """

    def __init__(
        self,
        requests_per_second: float = 4.5,
        burst_capacity: int = 5,
    ) -> None:
        self._rps = requests_per_second
        self._burst = burst_capacity
        # aiolimiter.AsyncLimiter(max_rate, time_period)
        # max_rate = burst_capacity; time_period = burst_capacity / rps
        self._limiter = AsyncLimiter(
            max_rate=float(burst_capacity),
            time_period=burst_capacity / requests_per_second,
        )
        logger.debug(
            "rate_limiter_created",
            requests_per_second=requests_per_second,
            burst_capacity=burst_capacity,
        )

    async def __aenter__(self) -> EtherscanRateLimiter:
        await self._limiter.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        pass  # aiolimiter releases the token automatically on acquire

    @property
    def requests_per_second(self) -> float:
        return self._rps

    @property
    def burst_capacity(self) -> int:
        return self._burst


# ─────────────────────────────────────────────────────────────────────────────
# No-op stub for tests
# ─────────────────────────────────────────────────────────────────────────────


class NullRateLimiter:
    """
    No-op rate limiter for unit tests.

    Satisfies the same `async with limiter` interface as EtherscanRateLimiter
    without sleeping or importing aiolimiter. Inject via:

        app.dependency_overrides[get_rate_limiter] = lambda: NullRateLimiter()
    """

    async def __aenter__(self) -> NullRateLimiter:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────


def create_rate_limiter(settings: Settings) -> EtherscanRateLimiter:
    """
    Construct an EtherscanRateLimiter from application settings.

    Call once from `main.py` lifespan, then pass the result to
    `dependencies.set_rate_limiter()`.

    Args:
        settings: Application settings (reads rate_limiter sub-model).

    Returns:
        Configured EtherscanRateLimiter instance.
    """
    rl = settings.rate_limiter
    return EtherscanRateLimiter(
        requests_per_second=rl.requests_per_second,
        burst_capacity=rl.burst_capacity,
    )
