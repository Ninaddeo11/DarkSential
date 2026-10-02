"""Pluggable dependency health checks.

Subsystems register an async check; readiness runs them concurrently with a
timeout. Failures report only the exception type so internal details (hosts,
credentials in connection strings) never leak through the API.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Literal

from pydantic import BaseModel

log = logging.getLogger(__name__)

CheckStatus = Literal["ok", "degraded", "error", "not_configured"]


class CheckResult(BaseModel):
    status: CheckStatus
    detail: str | None = None
    latency_ms: float | None = None


HealthCheck = Callable[[], Awaitable[CheckResult]]


class HealthRegistry:
    def __init__(self, timeout_s: float = 2.0) -> None:
        self._checks: dict[str, HealthCheck] = {}
        self._timeout_s = timeout_s

    def register(self, name: str, check: HealthCheck) -> None:
        if name in self._checks:
            raise ValueError(f"health check already registered: {name}")
        self._checks[name] = check

    def register_static(self, name: str, status: CheckStatus, detail: str | None = None) -> None:
        result = CheckResult(status=status, detail=detail)

        async def _static() -> CheckResult:
            return result

        self.register(name, _static)

    async def _run_one(self, name: str, check: HealthCheck) -> CheckResult:
        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(check(), timeout=self._timeout_s)
        except TimeoutError:
            result = CheckResult(status="error", detail="timeout")
        except Exception as exc:
            log.warning("health check failed", extra={"check": name, "error": type(exc).__name__})
            result = CheckResult(status="error", detail=type(exc).__name__)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        return result.model_copy(update={"latency_ms": elapsed})

    async def run(self) -> dict[str, CheckResult]:
        names = list(self._checks)
        results = await asyncio.gather(*(self._run_one(n, self._checks[n]) for n in names))
        return dict(zip(names, results, strict=True))
