"""Liveness and readiness endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel

from app import __version__
from app.core.health import CheckResult, HealthRegistry

router = APIRouter(prefix="/api/health", tags=["health"])


class LivenessResponse(BaseModel):
    status: Literal["ok"]
    version: str
    env: str
    deployment: str
    dry_run: bool
    offline_mode: bool


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, CheckResult]


@router.get("", response_model=LivenessResponse)
def liveness(request: Request) -> LivenessResponse:
    settings = request.app.state.settings
    return LivenessResponse(
        status="ok",
        version=__version__,
        env=settings.env,
        deployment=settings.deployment,
        dry_run=settings.dry_run,
        offline_mode=settings.offline_mode,
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness(request: Request, response: Response) -> ReadinessResponse:
    registry: HealthRegistry = request.app.state.health
    checks = await registry.run()
    ready = all(result.status != "error" for result in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="ready" if ready else "not_ready", checks=checks)
