from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from app.core.config import Settings
from app.core.db import init_db, make_engine, make_session_factory
from app.feeds import jobs
from app.feeds.config import FeedsFile, load_feeds_config
from app.feeds.runner import FeedRunner
from app.feeds.scheduler import AGING_JOB_ID, FeedScheduler, feed_job_id
from app.graph.memory import InMemoryGraphStore
from tests.conftest import SPACY, SettingsFactory

T0 = datetime(2026, 10, 1, tzinfo=UTC)

_engines: list[Engine] = []


@pytest.fixture(autouse=True)
def _dispose_engines() -> Iterator[None]:
    yield
    while _engines:
        _engines.pop().dispose()


def engine_for(settings: Settings) -> Engine:
    engine = make_engine(settings.database_url)
    _engines.append(engine)
    return engine


def make_runner(settings: Settings, feeds: FeedsFile | None = None) -> FeedRunner:
    engine = engine_for(settings)
    init_db(engine)
    return FeedRunner(
        settings,
        feeds or load_feeds_config(settings.feeds_config_path),
        InMemoryGraphStore(),
        make_session_factory(engine),
        clock=lambda: T0,
    )


def test_run_all_offline(settings: Settings) -> None:
    runner = make_runner(settings)
    results = runner.run_all()
    names = [r.feed for r in results]
    assert names[0] == "mitre_attack"
    assert names[-1] == "darkweb"
    by_name = {r.feed: r for r in results}
    for name in ("mitre_attack", "cisa_kev", "nvd_cve", "feodo", "threatfox", "urlhaus"):
        assert by_name[name].status == "success", by_name[name].error
        assert by_name[name].mode == "mock"
        assert by_name[name].objects > 0
    assert by_name["threatfox"].rejected == 1
    assert by_name["darkweb"].status == ("success" if SPACY else "failed")

    statuses = {s.name: s for s in runner.statuses(lambda _: None)}
    kev = statuses["cisa_kev"]
    assert kev.last_run is not None
    assert kev.last_run.status == "success"
    assert kev.last_success_at == T0
    assert kev.running is False
    assert kev.next_run_at is None


def test_skipped_when_credentials_missing(make_settings: SettingsFactory) -> None:
    runner = make_runner(make_settings(offline_mode=False))
    result = runner.run("urlhaus")
    assert result.status == "skipped"
    assert "abusech_auth_key" in (result.error or "")
    status = next(s for s in runner.statuses(lambda _: None) if s.name == "urlhaus")
    assert status.mode == "missing_credentials"
    assert status.last_run is not None
    assert status.last_run.status == "skipped"
    assert status.last_success_at is None


def test_failure_is_recorded_and_redacted(
    make_settings: SettingsFactory, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "super-secret-nvd-key"
    s = make_settings(nvd_api_key=secret, fixtures_dir=tmp_path)  # fixture file missing
    (tmp_path / "nvd").mkdir()
    (tmp_path / "nvd" / "nvd.sample.json").write_text(f'{{"broken {secret}', encoding="utf-8")
    runner = make_runner(s)
    with caplog.at_level(logging.ERROR):
        result = runner.run("nvd_cve")
    assert result.status == "failed"
    assert result.error
    assert "JSONDecodeError" in result.error
    assert secret not in result.error


def test_unknown_feed_and_concurrency_guard(settings: Settings) -> None:
    runner = make_runner(settings)
    with pytest.raises(KeyError):
        runner.run("nope")
    runner._running.add("feodo")
    with pytest.raises(RuntimeError, match="already running"):
        runner.run("feodo")
    assert next(s for s in runner.statuses(lambda _: None) if s.name == "feodo").running


def test_age_delegates_to_graph(settings: Settings) -> None:
    runner = make_runner(settings)
    runner.run("feodo")
    runner.clock = lambda: T0 + timedelta(days=15)
    assert runner.age().stale == 5


def test_jobs_without_runner_are_noops(caplog: pytest.LogCaptureFixture) -> None:
    jobs.set_runner(None)
    with caplog.at_level(logging.WARNING):
        jobs.run_feed_job("feodo")
        jobs.run_aging_job()
    assert "no runner registered" in caplog.text


def test_jobs_delegate(settings: Settings) -> None:
    runner = make_runner(settings)
    jobs.set_runner(runner)
    try:
        jobs.run_feed_job("feodo")
        jobs.run_aging_job()
    finally:
        jobs.set_runner(None)
    assert next(s for s in runner.statuses(lambda _: None) if s.name == "feodo").last_run


def test_scheduler_persists_jobs_across_restarts(settings: Settings) -> None:
    feeds = load_feeds_config(settings.feeds_config_path)
    first = FeedScheduler(engine_for(settings), feeds, jitter_seconds=0)
    first.start()
    try:
        assert first.running
        assert feed_job_id("cisa_kev") in first.job_ids()
        assert AGING_JOB_ID in first.job_ids()
        next_kev = first.next_run("cisa_kev")
        assert next_kev is not None
    finally:
        first.shutdown()

    # Restart with one feed disabled and one interval changed.
    changed = feeds.model_copy(
        update={
            "feeds": {
                **feeds.feeds,
                "feodo": feeds.feeds["feodo"].model_copy(update={"enabled": False}),
                "urlhaus": feeds.feeds["urlhaus"].model_copy(update={"interval_minutes": 5}),
            }
        }
    )
    second = FeedScheduler(engine_for(settings), changed, jitter_seconds=0)
    second.start()
    try:
        assert second.next_run("cisa_kev") == next_kev  # persisted, not reset
        assert feed_job_id("feodo") not in second.job_ids()
        assert second.next_run("feodo") is None
        urlhaus_next = second.next_run("urlhaus")
        assert urlhaus_next is not None
        assert urlhaus_next - datetime.now(UTC) <= timedelta(minutes=5, seconds=5)
    finally:
        second.shutdown()
    assert not second.running


def test_runner_thread_safety(settings: Settings) -> None:
    runner = make_runner(settings)
    errors: list[BaseException] = []

    def run(name: str) -> None:
        try:
            runner.run(name)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(n,)) for n in ("cisa_kev", "feodo", "urlhaus")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
