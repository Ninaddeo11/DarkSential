"""Per-client token-bucket rate limiting for the API (threat model O6).

Three budgets per client address: logins (brute force), mutations (operator
actions) and reads. Health endpoints are exempt so orchestrators can probe.
Buckets live in memory: one API process per lab, so no shared store is needed;
behind several replicas each would enforce its own budget.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.core.config import Settings

MAX_CLIENTS = 10_000  # bound memory: idle buckets are evicted beyond this


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def take(self, client: str, budget: str, per_minute: int) -> float:
        """Consume one token; returns 0 if allowed, else seconds until one is available."""
        rate = per_minute / 60.0
        now = self._clock()
        with self._lock:
            key = (client, budget)
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= MAX_CLIENTS:
                    self._evict(now)
                bucket = self._buckets[key] = _Bucket(tokens=float(per_minute), updated=now)
            bucket.tokens = min(per_minute, bucket.tokens + (now - bucket.updated) * rate)
            bucket.updated = now
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return 0.0
            return (1 - bucket.tokens) / rate

    def _evict(self, now: float) -> None:
        # Full buckets carry no state worth keeping; drop the stalest half first.
        stale = sorted(self._buckets.items(), key=lambda kv: kv[1].updated)
        for key, _ in stale[: len(stale) // 2 or 1]:
            del self._buckets[key]


def budget_for(method: str, path: str, settings: Settings) -> tuple[str, int] | None:
    if not path.startswith("/api/") or path.startswith("/api/health"):
        return None
    if path == "/api/auth/login":
        return "login", settings.rate_limit_logins_per_minute
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "mutation", settings.rate_limit_mutations_per_minute
    return "read", settings.rate_limit_reads_per_minute


def retry_after_header(seconds: float) -> str:
    return str(max(1, math.ceil(seconds)))
