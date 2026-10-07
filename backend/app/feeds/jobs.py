"""Scheduler job entry points.

APScheduler's persistent job store pickles a *reference* to these functions plus
their arguments (a feed or job name only), so they must be importable
module-level callables. They resolve live objects registered at startup.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.feeds.runner import FeedRunner

log = logging.getLogger(__name__)

_runner: FeedRunner | None = None
_named: dict[str, Callable[[], object]] = {}


def set_runner(runner: FeedRunner | None) -> None:
    global _runner
    _runner = runner


def register(name: str, fn: Callable[[], object]) -> None:
    _named[name] = fn


def clear_named() -> None:
    _named.clear()


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


def run_named_job(name: str) -> None:
    fn = _named.get(name)
    if fn is None:
        log.warning("named job fired but not registered", extra={"job": name})
        return
    fn()
