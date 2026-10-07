"""Runs feeds end to end: fetch -> normalize (STIX) -> project -> graph upsert -> record."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.logging import Redactor
from app.feeds.base import Clock, utcnow
from app.feeds.config import FeedsFile
from app.feeds.registry import FeedUnavailableError, build_adapter
from app.feeds.status import FeedStatus, RunInfo, feed_mode
from app.graph.project import project
from app.graph.store import AgingStats, GraphStore
from app.intel.nlp import EntityExtractor, Gazetteer, GazetteerEntry
from app.models.feed_run import FeedRun

log = logging.getLogger(__name__)


@dataclass
class FeedRunResult:
    feed: str
    mode: str
    status: str
    started_at: datetime
    finished_at: datetime
    objects: int = 0
    rejected: int = 0
    nodes: int = 0
    edges: int = 0
    skipped_edges: int = 0
    error: str | None = None
    rejections: list[str] = field(default_factory=list)


class FeedRunner:
    def __init__(
        self,
        settings: Settings,
        feeds: FeedsFile,
        graph: GraphStore,
        sessions: sessionmaker[Session],
        clock: Clock = utcnow,
    ) -> None:
        self.settings = settings
        self.feeds = feeds
        self.graph = graph
        self.sessions = sessions
        self.clock = clock
        self._redactor = Redactor(settings.secret_values())
        self._running: set[str] = set()
        self._lock = threading.Lock()
        self._schema_ready = False
        # Called with the feed name after each successful run (e.g. re-link
        # detection rules to ATT&CK once mitre_attack has been ingested).
        self.on_success: list[Callable[[str], None]] = []

    # --- NLP gazetteer from the graph --------------------------------------------------

    def gazetteer(self) -> Gazetteer:
        return Gazetteer(
            entries=[
                GazetteerEntry(kind, name, tuple(aliases))
                for kind, name, aliases in self.graph.named_entities()
            ],
            technique_ids=frozenset(self.graph.technique_ids()),
        )

    def extractor(self) -> EntityExtractor:
        return EntityExtractor(self.gazetteer())

    # --- running --------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        if not self._schema_ready:
            self.graph.ensure_schema()
            self._schema_ready = True

    def run(self, name: str) -> FeedRunResult:
        cfg = self.feeds.feeds.get(name)
        if cfg is None:
            raise KeyError(f"unknown feed {name!r}")
        with self._lock:
            if name in self._running:
                raise RuntimeError(f"feed {name} is already running")
            self._running.add(name)
        started = self.clock()
        mode = feed_mode(self.settings, cfg)
        result = FeedRunResult(name, mode, "failed", started, started)
        adapter = None
        try:
            adapter = build_adapter(self.settings, cfg, self.extractor, self.clock)
            raw = adapter.fetch()
            normalized = adapter.normalize_to_stix(raw)
            result.objects = len(normalized.objects)
            result.rejected = len(normalized.rejected)
            result.rejections = [f"{r.ref}: {r.reason}" for r in normalized.rejected[:20]]
            self._ensure_schema()
            stats = self.graph.upsert(
                project(normalized.objects),
                source=name,
                confidence=cfg.confidence,
                ttl_days=cfg.ttl_days,
                seen_at=self.clock(),
            )
            result.nodes, result.edges = stats.nodes, stats.edges
            result.skipped_edges = stats.skipped_edges
            result.status = "success"
        except FeedUnavailableError as exc:
            result.status = "skipped"
            result.error = str(exc)
        except Exception as exc:
            result.error = self._redactor.text(f"{type(exc).__name__}: {exc}")[:1000]
            log.exception("feed run failed", extra={"feed": name})
        finally:
            if adapter is not None and adapter.ctx.fetcher is not None:
                adapter.ctx.fetcher.client.close()
            result.finished_at = self.clock()
            with self._lock:
                self._running.discard(name)
        self._record(result)
        if result.status == "success":
            for hook in self.on_success:
                try:
                    hook(name)
                except Exception:
                    log.exception("feed success hook failed", extra={"feed": name})
        log.info(
            "feed run finished",
            extra={
                "feed": name,
                "status": result.status,
                "mode": result.mode,
                "objects": result.objects,
                "rejected": result.rejected,
                "nodes": result.nodes,
                "edges": result.edges,
            },
        )
        return result

    def run_all(self) -> list[FeedRunResult]:
        # ATT&CK first so the NLP gazetteer is seeded before dark-web mentions.
        order = sorted(self.feeds.feeds, key=lambda n: (n != "mitre_attack", n == "darkweb", n))
        return [self.run(n) for n in order if self.feeds.feeds[n].enabled]

    def age(self) -> AgingStats:
        stats = self.graph.age_indicators(self.clock())
        log.info("indicator aging", extra={"stale": stats.stale, "purged": stats.purged})
        return stats

    def _record(self, r: FeedRunResult) -> None:
        with self.sessions.begin() as session:
            session.add(
                FeedRun(
                    feed=r.feed,
                    mode=r.mode,
                    status=r.status,
                    started_at=r.started_at,
                    finished_at=r.finished_at,
                    objects=r.objects,
                    rejected=r.rejected,
                    nodes=r.nodes,
                    edges=r.edges,
                    skipped_edges=r.skipped_edges,
                    error=r.error,
                )
            )

    # --- status ---------------------------------------------------------------------

    def statuses(self, next_run: Callable[[str], datetime | None]) -> list[FeedStatus]:
        out: list[FeedStatus] = []
        with self.sessions() as session:
            for cfg in self.feeds.feeds.values():
                last = session.scalars(
                    select(FeedRun)
                    .where(FeedRun.feed == cfg.name)
                    .order_by(FeedRun.started_at.desc(), FeedRun.id.desc())
                    .limit(1)
                ).first()
                last_success = session.scalar(
                    select(func.max(FeedRun.finished_at)).where(
                        FeedRun.feed == cfg.name, FeedRun.status == "success"
                    )
                )
                out.append(
                    FeedStatus(
                        name=cfg.name,
                        enabled=cfg.enabled,
                        mode=feed_mode(self.settings, cfg),
                        interval_minutes=cfg.interval_minutes,
                        ttl_days=cfg.ttl_days,
                        confidence=cfg.confidence,
                        requires=cfg.requires,
                        running=cfg.name in self._running,
                        next_run_at=next_run(cfg.name),
                        last_run=RunInfo(
                            started_at=last.started_at,
                            finished_at=last.finished_at,
                            status=last.status,  # type: ignore[arg-type]
                            objects=last.objects,
                            rejected=last.rejected,
                            nodes=last.nodes,
                            edges=last.edges,
                            error=last.error,
                        )
                        if last
                        else None,
                        last_success_at=_as_utc(last_success),
                    )
                )
        return out


def _as_utc(value: datetime | None) -> datetime | None:
    from datetime import UTC

    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value
