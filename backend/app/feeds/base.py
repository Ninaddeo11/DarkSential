"""FeedAdapter contract and MockAdapter.

Every feed implements ``fetch()`` (transport) and ``normalize_to_stix()``
(pure transformation to validated STIX 2.1 dicts). Rate limiting, retry with
backoff + jitter, and caching live in :class:`~app.feeds.http.HttpFetcher`,
which every live adapter uses for I/O.

``MockAdapter`` swaps only the transport: it replays a fixture file and runs
the *real* adapter's ``normalize_to_stix``, so offline mode exercises exactly
the production parsing code.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeAlias

from app.core.config import Settings
from app.feeds.config import FeedConfig
from app.feeds.http import HttpFetcher
from app.intel.stix import validate

log = logging.getLogger(__name__)

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Rejection:
    ref: str
    reason: str


@dataclass
class NormalizeResult:
    objects: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[Rejection] = field(default_factory=list)


@dataclass
class AdapterContext:
    settings: Settings
    config: FeedConfig
    fetcher: HttpFetcher | None  # None for mocks
    clock: Clock = utcnow


# A stix2 object (the library is untyped) or a STIX dict.
Candidate: TypeAlias = Any


class FeedAdapter(ABC):
    name: str

    def __init__(self, ctx: AdapterContext) -> None:
        self.ctx = ctx

    @property
    def confidence(self) -> int:
        return self.ctx.config.confidence

    def _fetcher(self) -> HttpFetcher:
        if self.ctx.fetcher is None:
            raise RuntimeError(f"{self.name}: no HTTP fetcher configured (offline?)")
        return self.ctx.fetcher

    @abstractmethod
    def fetch(self) -> Any:
        """Retrieve the raw payload (JSON-compatible)."""

    @abstractmethod
    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        """Yield STIX objects (or rejections) built from the raw payload."""

    def normalize_to_stix(self, raw: Any) -> NormalizeResult:
        """Build and validate STIX 2.1 objects; invalid items are rejected, not fatal."""
        result = NormalizeResult()
        seen: set[str] = set()
        for item in self.candidates(raw):
            if isinstance(item, Rejection):
                result.rejected.append(item)
                continue
            ref = item.get("id", "?") if isinstance(item, dict) else str(item.id)
            try:
                obj = validate(item)
            except Exception as exc:  # stix2 raises a variety of exception types
                result.rejected.append(Rejection(ref=str(ref), reason=type(exc).__name__))
                continue
            if obj["id"] in seen:
                continue
            seen.add(obj["id"])
            result.objects.append(obj)
        if result.rejected:
            log.info(
                "feed items rejected",
                extra={"feed": self.name, "rejected": len(result.rejected)},
            )
        return result


class MockAdapter(FeedAdapter):
    """Replays ``/fixtures/<config.fixture>`` through a real adapter's normalizer."""

    def __init__(self, inner: FeedAdapter, fixture_path: Path) -> None:
        super().__init__(inner.ctx)
        self.inner = inner
        self.name = inner.name
        self.fixture_path = fixture_path

    def fetch(self) -> Any:
        return json.loads(self.fixture_path.read_text(encoding="utf-8"))

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        return self.inner.candidates(raw)
