"""Feed status models and mode resolution (core-only; safe for hosted mode)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.core.config import Settings
from app.feeds.config import FeedConfig, FeedsFile

FeedMode = Literal["mock", "live", "missing_credentials", "disabled"]


def feed_mode(settings: Settings, cfg: FeedConfig) -> FeedMode:
    if not cfg.enabled:
        return "disabled"
    if settings.offline_mode:
        return "mock"
    if cfg.requires and not getattr(settings, cfg.requires, None):
        return "missing_credentials"
    return "live"


class RunInfo(BaseModel):
    started_at: datetime
    finished_at: datetime
    status: Literal["success", "failed", "skipped"]
    objects: int
    rejected: int
    nodes: int
    edges: int
    error: str | None


class FeedStatus(BaseModel):
    name: str
    enabled: bool
    mode: FeedMode
    interval_minutes: int
    ttl_days: int
    confidence: int
    requires: str | None
    running: bool = False
    next_run_at: datetime | None = None
    last_run: RunInfo | None = None
    last_success_at: datetime | None = None


class FeedStatusResponse(BaseModel):
    scheduler: Literal["running", "stopped", "disabled", "unavailable_hosted"]
    graph_backend: Literal["neo4j", "memory", "none"]
    feeds: list[FeedStatus]


def static_status(settings: Settings, feeds: FeedsFile) -> FeedStatusResponse:
    """Config-only view (hosted deployments have no scheduler, DB or graph)."""
    return FeedStatusResponse(
        scheduler="unavailable_hosted",
        graph_backend="none",
        feeds=[
            FeedStatus(
                name=cfg.name,
                enabled=cfg.enabled,
                mode=feed_mode(settings, cfg),
                interval_minutes=cfg.interval_minutes,
                ttl_days=cfg.ttl_days,
                confidence=cfg.confidence,
                requires=cfg.requires,
            )
            for cfg in feeds.feeds.values()
        ],
    )
