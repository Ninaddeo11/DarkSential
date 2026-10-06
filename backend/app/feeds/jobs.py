"""Scheduler job entry points.

APScheduler's persistent job store pickles a *reference* to these functions plus
their arguments (just the feed name), so they must be importable module-level
callables. They resolve the live runner registered at startup.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.feeds.runner import FeedRunner

log = logging.getLogger(__name__)

_runner: FeedRunner | None = None


def set_runner(runner: FeedRunner | None) -> None:
    global _runner
    _runner = runner


def run_feed_job(name: str) -> None:
    if _runner is None:
        log.warning("feed job fired with no runner registered", extra={"feed": name})
        return
    _runner.run(name)


def run_aging_job() -> None:
    if _runner is None:
        log.warning("aging job fired with no runner registered")
        return
    _runner.age()
