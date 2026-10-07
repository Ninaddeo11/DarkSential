from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.behavior.events import TrafficEvent
from app.behavior.pipeline import FLEET_KEY, BehaviorPipeline
from app.core.config import Settings
from app.core.events import Event
from app.models.device import Detection, DeviceBaseline
from app.runtime import LabRuntime
from app.simulation.traffic import SimDevice, TrafficSimulator, merge
from tests.conftest import SKLEARN, SettingsFactory

START = datetime(2026, 10, 1, 8, tzinfo=UTC)


@pytest.fixture(scope="session")
def models_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One Isolation Forest per test session (training takes a couple of seconds)."""
    return tmp_path_factory.mktemp("models")


@pytest.fixture
def runtime(make_settings: SettingsFactory, models_dir: Path) -> Iterator[LabRuntime]:
    from app.feeds.config import load_feeds_config

    settings = make_settings(models_dir=models_dir, iforest_autotrain=SKLEARN)
    rt = LabRuntime.build(settings, load_feeds_config(settings.feeds_config_path))
    rt.start()
    yield rt
    rt.stop()


def scenario(seed: int = 42) -> tuple[list[TrafficEvent], dict[tuple[str, datetime], set[str]]]:
    sim = TrafficSimulator(seed=seed)
    t = START + timedelta(minutes=40)
    rogue = SimDevice("rogue", "02:00:5e:aa:bb:cc", "192.168.50.66", "esp32_sensor")
    stream = merge(
        sim.normal(START, 45),
        sim.mqtt_flood(sim.device("esp32-node"), t, minutes=2, per_minute=500),
        sim.wildcard_subscribe(sim.device("plug-desk"), t + timedelta(minutes=1)),
        sim.restricted_publish(sim.device("plug-desk"), t + timedelta(minutes=2)),
        sim.brute_force(sim.device("cam-front"), t + timedelta(minutes=1)),
        sim.port_scan(sim.device("thermo-hall"), t + timedelta(minutes=3)),
        sim.port_scan(rogue, t + timedelta(minutes=2), ports=120),
    )
    names = {d.ip: d.name for d in (*sim.fleet, rogue)}
    truth: dict[tuple[str, datetime], set[str]] = {}
    for le in stream:
        truth.setdefault(
            (names[le.event.src_ip or ""], le.event.ts.replace(second=0, microsecond=0)), set()
        ).add(le.label)
    return [le.event for le in stream], truth


def test_end_to_end_detection_against_ground_truth(runtime: LabRuntime) -> None:
    seen: list[Event] = []
    runtime.bus.subscribe(seen.append)
    events, truth = scenario()
    results = runtime.pipeline.ingest(events) + runtime.pipeline.flush()
    ip_name = {
        "192.168.50.21": "cam-front",
        "192.168.50.22": "thermo-hall",
        "192.168.50.23": "plug-desk",
        "192.168.50.24": "esp32-node",
        "192.168.50.66": "rogue",
    }

    def name(node_id: str) -> str:
        dev = runtime.registry.get(node_id)
        assert dev is not None
        return ip_name[dev.ip or ""]

    flagged = {
        (name(r.node_id), r.window_start): r for r in results if r.anomaly.is_anomaly or r.rule_hits
    }
    attacks = {k for k, v in truth.items() if v - {"normal"}}
    assert attacks <= set(flagged), f"missed: {attacks - set(flagged)}"
    false_pos = set(flagged) - attacks
    if SKLEARN:
        # z-scores + Isolation Forest: 0 FP over 20 seeds x ~170 normal windows.
        assert runtime.pipeline.scorer.model is not None
        assert false_pos == set(), "false positives on normal windows"
    else:
        # z-scores alone: measured ~0.3% FPR over 20 seeds; allow 1%.
        assert len(false_pos) <= 0.01 * (len(truth) - len(attacks))

    def rules_for(label: str) -> set[str]:
        keys = [k for k, v in truth.items() if label in v]
        return {h.rule_id for k in keys for h in flagged[k].rule_hits}

    assert "mqtt_connect_flood" in rules_for("mqtt_flood")
    assert rules_for("wildcard_subscribe") == {"mqtt_wildcard_subscription"}
    assert rules_for("restricted_publish") == {"mqtt_restricted_publish"}
    assert "credential_brute_force" in rules_for("brute_force")
    assert "network_scan" in rules_for("port_scan")
    assert "credential_brute_force" not in rules_for("port_scan")  # refused SYN != failed login

    # The rogue device was created from traffic alone and scored cold.
    rogue = flagged[next(k for k in flagged if k[0] == "rogue")]
    assert rogue.anomaly.cold_start
    types = [e.type for e in seen]
    assert types.count("DEVICE_CONNECTED") == 5  # 4 fleet devices + rogue
    assert types.count("ANOMALY_DETECTED") >= len(attacks)

    # Persisted detections carry techniques and evidence.
    with runtime.sessions() as session:
        rows = session.scalars(select(Detection)).all()
        rule_rows = [d for d in rows if d.kind == "rule"]
        assert rule_rows
        assert all(d.techniques for d in rule_rows)
        assert all(d.evidence["rule"]["evidence"] for d in rule_rows)
        flood = next(d for d in rule_rows if d.rule_id == "mqtt_connect_flood")
        assert flood.severity == "high"
        assert flood.score == 0.8
        assert "mqtt_connect_rate" in flood.summary


def test_only_clean_windows_are_learned(runtime: LabRuntime) -> None:
    events, _ = scenario()
    results = runtime.pipeline.ingest(events) + runtime.pipeline.flush()
    for r in results:
        assert r.learned == (not r.anomaly.is_anomaly and not r.rule_hits)
    learned = sum(r.learned for r in results)
    assert runtime.pipeline.baseline(FLEET_KEY).windows == learned
    esp = runtime.registry.resolve(ip="192.168.50.24")
    assert esp is not None
    base = runtime.pipeline.baseline(esp)
    assert base.windows >= 30
    assert "mqtt" in base.protocols
    # Flood windows never entered the baseline: mean connect rate stays tiny.
    assert base.stats["mqtt_connect_rate"].mean < 5


def test_baselines_persist_across_restart(settings: Settings) -> None:
    from app.feeds.config import load_feeds_config

    feeds = load_feeds_config(settings.feeds_config_path)
    rt = LabRuntime.build(settings, feeds)
    events, _ = scenario()
    rt.pipeline.ingest(events[: len(events) // 2])
    rt.pipeline.flush()
    snapshot = {k: b.windows for k, b in rt.pipeline._baselines.items()}
    with rt.sessions() as session:
        assert session.scalars(select(DeviceBaseline)).all()
    rt.stop()
    rt2 = LabRuntime.build(settings, feeds)
    try:
        assert {k: b.windows for k, b in rt2.pipeline._baselines.items()} == snapshot
    finally:
        rt2.stop()


def test_tick_closes_windows_and_empty_flush(runtime: LabRuntime) -> None:
    p: BehaviorPipeline = runtime.pipeline
    assert p.flush() == []
    ev = TrafficEvent(
        ts=START + timedelta(seconds=5),
        src_mac="24:0a:c4:40:00:04",
        src_ip="192.168.50.24",
        dst_port=8883,
        proto="mqtt",
    )
    assert p.ingest([ev]) == []
    assert p.tick(START + timedelta(seconds=30)) == []  # window still open
    closed = p.tick(START + timedelta(seconds=61))
    assert len(closed) == 1
    assert closed[0].events == 1
    assert p.latest[closed[0].node_id] == closed[0]


def test_events_without_identity_are_dropped(runtime: LabRuntime) -> None:
    ev = TrafficEvent(ts=START, proto="tcp")
    assert runtime.pipeline.ingest([ev]) == []
    assert runtime.registry.list() == []


def test_wifi_alert_recorded(runtime: LabRuntime) -> None:
    runtime.pipeline.record_alert(
        "dev-ap0000000000000", "wifi_deauth_flood", {"frames": 120, "rate_per_min": 120.0}, START
    )
    with runtime.sessions() as session:
        d = session.scalars(select(Detection)).one()
    assert d.rule_id == "wifi_deauth_flood"
    assert d.techniques == ["T1498", "T0814"]
    assert d.severity == "high"
    assert "frames=120" in d.summary


def test_simulator_is_deterministic() -> None:
    a = TrafficSimulator(seed=9).normal(START, 10)
    b = TrafficSimulator(seed=9).normal(START, 10)
    c = TrafficSimulator(seed=10).normal(START, 10)
    assert [x.event for x in a] == [x.event for x in b]
    assert [x.event for x in a] != [x.event for x in c]
    assert all(x.label == "normal" for x in a)


def test_runtime_links_rules_after_attack_import(make_settings: SettingsFactory) -> None:
    from app.feeds.config import load_feeds_config

    s = make_settings()
    rt = LabRuntime.build(s, load_feeds_config(s.feeds_config_path))
    rt.start()
    try:
        assert rt.graph.techniques_for_behavior("network_scan") == []  # no ATT&CK yet
        rt.runner.run("mitre_attack")  # success hook re-links
        assert [t.external_id for t in rt.graph.techniques_for_behavior("network_scan")] == [
            "T1046"
        ]
        assert rt.link_rules() == {}  # every rule technique exists in the fixture
    finally:
        rt.stop()
