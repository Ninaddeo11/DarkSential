"""Feed schedule/limits configuration (config/feeds.yaml).

Core-only dependencies (pydantic + yaml): hosted deployments read it for the
status endpoint without importing any lab code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

FEED_NAMES = (
    "cisa_kev",
    "nvd_cve",
    "mitre_attack",
    "urlhaus",
    "threatfox",
    "feodo",
    "darkweb",
)


class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requests: int = Field(ge=1)
    per_seconds: float = Field(gt=0)


class FeedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    enabled: bool = True
    interval_minutes: int = Field(ge=1)
    confidence: int = Field(ge=0, le=100)
    ttl_days: int = Field(ge=1)
    cache_ttl_seconds: int = Field(ge=0)
    timeout_seconds: float = Field(gt=0)
    max_response_mb: int = Field(ge=1)
    rate_limit: RateLimit
    rate_limit_with_key: RateLimit | None = None
    requires: str | None = None
    fixture: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)

    @property
    def max_response_bytes(self) -> int:
        return self.max_response_mb * 1024 * 1024


class FeedsFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    feeds: dict[str, FeedConfig]

    @model_validator(mode="after")
    def _known_names(self) -> FeedsFile:
        unknown = set(self.feeds) - set(FEED_NAMES)
        if unknown:
            raise ValueError(f"unknown feeds in config: {sorted(unknown)}")
        return self


def load_feeds_config(path: Path) -> FeedsFile:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults: dict[str, Any] = raw.get("defaults", {})
    feeds: dict[str, Any] = {}
    for name, cfg in (raw.get("feeds") or {}).items():
        feeds[name] = {**defaults, **(cfg or {}), "name": name}
    return FeedsFile.model_validate({"feeds": feeds})
