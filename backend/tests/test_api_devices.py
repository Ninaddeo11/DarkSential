from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.db import init_db, make_engine
from app.detect.nmap_scan import parse_nmap_xml
from app.main import create_app
from app.simulation.traffic import TrafficSimulator
from tests.conftest import FIXTURES, SettingsFactory

START = datetime(2026, 10, 1, 8, tzinfo=UTC)


@pytest.fixture
def lab(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as client:
        rt = client.app.state.runtime  # type: ignore[attr-defined]
        rt.runner.run("mitre_attack")
        for obs in parse_nmap_xml((FIXTURES / "events" / "lab-scan.nmap.xml").read_bytes()):
            rt.registry.observe(obs.model_copy(update={"ts": START}))
        sim = TrafficSimulator(seed=1)
        esp = sim.device("esp32-node")
        events = [le.event for le in sim.normal(START, 5)]
        events += [le.event for le in sim.mqtt_flood(esp, START + timedelta(minutes=5), 1)]
        rt.pipeline.ingest(events)
        rt.pipeline.flush()
        yield client


def test_devices_and_detail(lab: TestClient) -> None:
    devices = lab.get("/api/devices").json()
    assert len(devices) == 6
    gw = next(d for d in devices if d["ip"] == "192.168.50.1")
    assert gw["trust"] == "unknown"
    assert any("archer_ax21" in c["cpe"] for c in gw["cpes"])
    esp = next(d for d in devices if d["ip"] == "192.168.50.24")
    detail = lab.get(f"/api/devices/{esp['node_id']}").json()
    assert detail["device"]["node_id"] == esp["node_id"]
    assert detail["latest_window"]["features"]["mqtt_connect_rate"] > 100
    assert detail["baseline"]["mature"] is False
    assert any(d["rule_id"] == "mqtt_connect_flood" for d in detail["detections"])
    assert lab.get("/api/devices/dev-0000000000000000").status_code == 404
    assert lab.get("/api/devices/not-a-node").status_code == 404


def test_detections_events_rules_capabilities(lab: TestClient) -> None:
    detections = lab.get("/api/detections", params={"limit": 5}).json()
    assert 0 < len(detections) <= 5
    assert lab.get("/api/detections", params={"limit": 0}).status_code == 422
    events = lab.get("/api/events", params={"limit": 1000}).json()
    types = {e["type"] for e in events}
    assert {"DEVICE_CONNECTED", "DEVICE_PROFILED", "ANOMALY_DETECTED"} <= types
    newest = events[-1]["seq"]
    assert lab.get("/api/events", params={"after_seq": newest}).json() == []
    rules = {r["id"]: r for r in lab.get("/api/rules").json()}
    assert rules["network_scan"]["linked"] == ["T1046"]
    caps = lab.get("/api/discovery/capabilities").json()
    assert caps["nmap"]["active"] is False


def test_hosted_mode_devices_unavailable(make_settings: SettingsFactory) -> None:
    with TestClient(create_app(make_settings(deployment="hosted"))) as client:
        assert client.get("/api/devices").status_code == 503
        assert client.get("/api/events").json() == []


def test_phase1_database_is_stamped_and_upgraded(tmp_path: Path) -> None:
    db = tmp_path / "legacy.sqlite3"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE feed_runs (id INTEGER PRIMARY KEY, feed VARCHAR(64), mode VARCHAR(32), "
        "status VARCHAR(16), started_at DATETIME, finished_at DATETIME, objects INTEGER, "
        "rejected INTEGER, nodes INTEGER, edges INTEGER, skipped_edges INTEGER, error TEXT)"
    )
    con.execute(
        "INSERT INTO feed_runs (feed, mode, status, started_at, finished_at, objects, rejected,"
        " nodes, edges, skipped_edges) VALUES ('feodo','mock','success','2026-10-01 00:00:00',"
        "'2026-10-01 00:00:01',1,0,1,0,0)"
    )
    con.commit()
    con.close()
    engine = make_engine(f"sqlite:///{db.as_posix()}")
    init_db(engine)
    init_db(engine)  # idempotent
    engine.dispose()
    con = sqlite3.connect(db)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "feed_runs",
        "devices",
        "detections",
        "device_baselines",
        "risk_decisions",
        "alembic_version",
    } <= tables
    assert con.execute("SELECT version_num FROM alembic_version").fetchone() == ("0004",)
    assert con.execute("SELECT count(*) FROM feed_runs").fetchone() == (1,)  # history kept
    con.close()
