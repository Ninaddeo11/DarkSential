from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app import cli
from app.core.config import Settings
from app.detect import capabilities
from app.detect.capabilities import SourceStatus
from app.feeds.config import load_feeds_config
from app.runtime import LabRuntime
from app.simulation.traffic import TrafficSimulator
from tests.conftest import FIXTURES, SKLEARN, TEST_HMAC_KEY, SettingsFactory


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("DSN_DEVICE_ID_HMAC_KEY", TEST_HMAC_KEY)
    monkeypatch.setenv("DSN_DATABASE_URL", f"sqlite:///{(tmp_path / 'cli.sqlite3').as_posix()}")
    monkeypatch.setenv("DSN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("DSN_MODELS_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("DSN_IFOREST_AUTOTRAIN", "false")
    monkeypatch.setenv("DSN_XGB_AUTOTRAIN", "false")
    return tmp_path


def test_demo_phase2(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo-phase2"]) == 0
    out = capsys.readouterr().out
    assert "network_scan                high     T1046" in out
    assert "missing techniques: none" in out
    assert "plan: nmap -sV" in out
    assert "attack windows: 7, detected: 7, normal windows flagged: 0" in out
    assert "randomized_mac=True" in out
    assert "Isolation Forest" in out if SKLEARN else "z-scores only" in out
    assert "Phase 2 demo OK" in out


def test_device_commands(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    xml = FIXTURES / "events" / "lab-scan.nmap.xml"
    assert cli.main(["discover-xml", str(xml)]) == 0
    node_ids = json.loads(capsys.readouterr().out)
    assert len(node_ids) == 6
    assert cli.main(["approve", node_ids[0]]) == 0
    assert json.loads(capsys.readouterr().out)["trust"] == "approved"
    assert cli.main(["devices"]) == 0
    devices = json.loads(capsys.readouterr().out)
    assert {d["trust"] for d in devices} == {"approved", "unknown"}
    assert cli.main(["scan", "--profile", "ping"]) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    assert cli.main(["rules"]) == 0
    assert any(r["id"] == "mqtt_connect_flood" for r in json.loads(capsys.readouterr().out))


def test_replay_jsonl(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sim = TrafficSimulator(seed=4)
    start = datetime(2026, 10, 1, 8, tzinfo=UTC)
    events = [le.event for le in sim.mqtt_flood(sim.device("esp32-node"), start, minutes=1)]
    path = cli_env / "events.jsonl"
    path.write_text("\n".join(e.model_dump_json() for e in events) + "\n\n", encoding="utf-8")
    assert cli.main(["replay", str(path)]) == 0
    flagged = json.loads(capsys.readouterr().out)
    assert "mqtt_connect_flood" in flagged[0]["rules"]


def test_train_model_command(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("sklearn.ensemble")
    assert cli.main(["train-model"]) == 0
    meta = json.loads(capsys.readouterr().out)
    assert meta["n_samples"] > 1000
    assert (cli_env / "models" / "iforest.joblib").exists()


class FakeService:
    def __init__(self, *args: Any) -> None:
        self.args = args
        self.started: Any = None
        self.stopped = False

    def start(self, *args: Any) -> None:
        self.started = args

    def stop(self) -> None:
        self.stopped = True


def test_runtime_starts_only_capable_sources(
    make_settings: SettingsFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    s: Settings = make_settings(wifi_monitor_iface="wlan0mon")
    active = SourceStatus(enabled=True, available=True, active=True, reason="ok")
    monkeypatch.setattr(
        capabilities,
        "report",
        lambda _: {"nmap": active, "passive": active, "ble": active, "wifi": active},
    )
    monkeypatch.setattr("app.detect.passive.PassiveObserver", FakeService)
    monkeypatch.setattr("app.detect.ble.BleScanner", FakeService)
    monkeypatch.setattr("app.detect.wifi.DeauthMonitor", FakeService)
    rt = LabRuntime.build(
        s.model_copy(update={"scheduler_enabled": True}), load_feeds_config(s.feeds_config_path)
    )
    rt.start()
    try:
        assert len(rt._services) == 3
        assert rt._services[2].started == ("wlan0mon",)
        assert rt.scheduler is not None
        assert "job:nmap_discovery" in rt.scheduler.job_ids()
        assert "job:trust_refresh" in rt.scheduler.job_ids()
        assert rt.run_nmap() == 0  # DRY_RUN: plan only, no hosts
        wifi_alert = rt._services[2].args[1]
        from app.detect.wifi import DeauthAlert

        wifi_alert(DeauthAlert("a" * 64, 99, 99.0, 60.0, {"deauth": 99}))
        assert rt.bus.recent()[-1].payload["rule_id"] == "wifi_deauth_flood"
    finally:
        services = list(rt._services)
        rt.stop()
    assert all(svc.stopped for svc in services)


def test_runtime_model_handling(make_settings: SettingsFactory, tmp_path: Path) -> None:
    from app.behavior.config import load_behavior_config
    from app.runtime import load_or_train_model

    s = make_settings(models_dir=tmp_path / "m", iforest_autotrain=False)
    cfg = load_behavior_config(s.behavior_config_path)
    assert load_or_train_model(s, cfg) is None  # no model and autotrain off
    if not SKLEARN:
        return
    s2 = s.model_copy(update={"iforest_autotrain": True})
    model = load_or_train_model(s2, cfg)
    assert model is not None
    (tmp_path / "m" / "iforest.joblib").write_bytes(b"tampered pickle")
    retrained = load_or_train_model(s2, cfg)  # integrity failure -> retrain, not unpickle
    assert retrained is not None
    from app.behavior.anomaly import IForestModel

    # The replacement on disk is validly signed again.
    assert IForestModel.load(tmp_path / "m", TEST_HMAC_KEY.encode()).p99 == retrained.p99
