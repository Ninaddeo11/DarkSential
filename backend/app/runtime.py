"""Lab runtime: DB, graph store, feed runner and scheduler.

Imported lazily by ``app.main`` only when ``deployment == "lab"``, so hosted
(serverless) deployments never import the heavy `lab` extra.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.db import init_db, make_engine, make_session_factory
from app.core.health import CheckResult
from app.feeds import jobs
from app.feeds.config import FeedsFile
from app.feeds.runner import FeedRunner
from app.feeds.scheduler import FeedScheduler
from app.feeds.status import FeedStatusResponse
from app.graph.memory import InMemoryGraphStore
from app.graph.store import GraphStore

log = logging.getLogger(__name__)


def build_graph_store(settings: Settings) -> GraphStore:
    if settings.neo4j_uri and settings.neo4j_password is not None:
        from app.graph.neo4j_store import Neo4jGraphStore

        return Neo4jGraphStore(
            settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password.get_secret_value()
        )
    log.warning("DSN_NEO4J_URI unset: using the in-memory graph (not persistent)")
    return InMemoryGraphStore()


@dataclass
class LabRuntime:
    settings: Settings
    engine: Engine
    sessions: sessionmaker[Session]
    graph: GraphStore
    runner: FeedRunner
    scheduler: FeedScheduler | None

    @classmethod
    def build(
        cls, settings: Settings, feeds: FeedsFile, graph: GraphStore | None = None
    ) -> LabRuntime:
        engine = make_engine(settings.database_url)
        init_db(engine)
        sessions = make_session_factory(engine)
        graph = graph or build_graph_store(settings)
        runner = FeedRunner(settings, feeds, graph, sessions)
        scheduler = FeedScheduler(engine, feeds) if settings.scheduler_enabled else None
        return cls(settings, engine, sessions, graph, runner, scheduler)

    @property
    def graph_backend(self) -> str:
        return "memory" if isinstance(self.graph, InMemoryGraphStore) else "neo4j"

    def start(self) -> None:
        try:
            self.graph.ensure_schema()
        except Exception as exc:
            # Readiness reports it; ingestion retries schema creation on first run.
            log.error("graph schema setup failed", extra={"error": type(exc).__name__})
        jobs.set_runner(self.runner)
        if self.scheduler:
            self.scheduler.start()

    def stop(self) -> None:
        if self.scheduler:
            self.scheduler.shutdown()
        jobs.set_runner(None)
        self.graph.close()
        self.engine.dispose()

    def feed_status(self) -> FeedStatusResponse:
        sched = self.scheduler
        return FeedStatusResponse(
            scheduler=("running" if sched.running else "stopped") if sched else "disabled",
            graph_backend=self.graph_backend,  # type: ignore[arg-type]
            feeds=self.runner.statuses(sched.next_run if sched else lambda _: None),
        )

    # --- health checks ---------------------------------------------------------------

    async def check_database(self) -> CheckResult:
        def probe() -> None:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))

        await asyncio.to_thread(probe)
        return CheckResult(status="ok")

    async def check_graph(self) -> CheckResult:
        await asyncio.to_thread(self.graph.ping)
        if self.graph_backend == "memory":
            return CheckResult(status="degraded", detail="in-memory graph (set DSN_NEO4J_URI)")
        return CheckResult(status="ok")
