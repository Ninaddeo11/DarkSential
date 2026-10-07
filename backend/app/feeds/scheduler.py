"""Persistent APScheduler setup: one interval job per enabled feed, plus aging.

Jobs live in the SQL job store, so schedules survive restarts. On startup an
existing job is kept as-is (preserving its persisted next run time) unless its
interval changed in config; jobs for disabled feeds are removed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import Engine

from app.feeds.config import FeedsFile

log = logging.getLogger(__name__)

AGING_JOB_ID = "maintenance:aging"
AGING_INTERVAL = timedelta(hours=1)


def feed_job_id(name: str) -> str:
    return f"feed:{name}"


class FeedScheduler:
    def __init__(
        self,
        engine: Engine,
        feeds: FeedsFile,
        *,
        jitter_seconds: int = 30,
        named_jobs: dict[str, int] | None = None,
    ) -> None:
        self._feeds = feeds
        self._jitter = jitter_seconds
        # name -> interval seconds; each runs app.feeds.jobs:run_named_job(name).
        self._named = dict(named_jobs or {})
        self._scheduler = BackgroundScheduler(
            jobstores={"default": SQLAlchemyJobStore(engine=engine, tablename="scheduler_jobs")},
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 900},
            timezone="UTC",
        )

    @property
    def running(self) -> bool:
        return bool(self._scheduler.running)

    def start(self) -> None:
        self._scheduler.start(paused=True)
        self.sync_jobs()
        self._scheduler.resume()
        log.info("scheduler started", extra={"jobs": [j.id for j in self._scheduler.get_jobs()]})

    def shutdown(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def sync_jobs(self) -> None:
        for cfg in self._feeds.feeds.values():
            job_id = feed_job_id(cfg.name)
            existing = self._scheduler.get_job(job_id)
            if not cfg.enabled:
                if existing:
                    self._scheduler.remove_job(job_id)
                continue
            interval = timedelta(minutes=cfg.interval_minutes)
            if existing and getattr(existing.trigger, "interval", None) == interval:
                continue
            self._scheduler.add_job(
                "app.feeds.jobs:run_feed_job",
                trigger=IntervalTrigger(minutes=cfg.interval_minutes, jitter=self._jitter),
                id=job_id,
                name=f"feed {cfg.name}",
                args=[cfg.name],
                replace_existing=True,
            )
        if self._scheduler.get_job(AGING_JOB_ID) is None:
            self._scheduler.add_job(
                "app.feeds.jobs:run_aging_job",
                trigger=IntervalTrigger(seconds=int(AGING_INTERVAL.total_seconds())),
                id=AGING_JOB_ID,
                name="indicator aging",
                replace_existing=True,
            )
        wanted = {f"job:{n}" for n in self._named}
        for job in self._scheduler.get_jobs():
            if job.id.startswith("job:") and job.id not in wanted:
                self._scheduler.remove_job(job.id)
        for name, seconds in self._named.items():
            job_id = f"job:{name}"
            existing = self._scheduler.get_job(job_id)
            if existing and getattr(existing.trigger, "interval", None) == timedelta(
                seconds=seconds
            ):
                continue
            self._scheduler.add_job(
                "app.feeds.jobs:run_named_job",
                trigger=IntervalTrigger(seconds=seconds, jitter=self._jitter),
                id=job_id,
                name=name,
                args=[name],
                replace_existing=True,
            )

    def schedule_once(self, job_id: str, func: str, run_at: datetime, args: list[object]) -> None:
        """Persistent one-shot job (e.g. quarantine recovery); replaces a same-id job."""
        self._scheduler.add_job(
            func,
            trigger=DateTrigger(run_date=run_at),
            id=job_id,
            name=job_id,
            args=args,
            replace_existing=True,
            misfire_grace_time=None,
        )

    def cancel(self, job_id: str) -> None:
        if self._scheduler.get_job(job_id) is not None:
            self._scheduler.remove_job(job_id)

    def next_run(self, feed: str) -> datetime | None:
        job = self._scheduler.get_job(feed_job_id(feed))
        return job.next_run_time if job else None

    def job_ids(self) -> list[str]:
        return sorted(j.id for j in self._scheduler.get_jobs())
