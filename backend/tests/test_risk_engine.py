from __future__ import annotations

import math
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.behavior.events import TrafficEvent
from app.core.events import Event
from app.detect.nmap_scan import parse_nmap_xml
from app.feeds.config import load_feeds_config
from app.main import create_app
from app.risk.engine import RiskEngine
from app.runtime import LabRuntime
from app.simulation.traffic import TrafficSimulator
from tests.conftest import FIXTURES, SKLEARN, SettingsFactory

START = datetime(2026, 10, 1, 8, tzinfo=UTC)
GATEWAY = "192.168.50.1"
ESP = "192.168.50.24"
FEODO_C2 = "162.243.103.246"


@pytest.fixture
def rt(make_settings: SettingsFactory) -> Iterator[LabRuntime]:
    s = make_settings(protected_hosts=[GATEWAY])
    runtime = LabRuntime.build(s, load_feeds_config(s.feeds_config_path))
    runtime.start()
    for feed in ("mitre_attack", "cisa_kev", "nvd_cve", "feodo"):
        assert runtime.runner.run(feed).status == "success"
    for obs in parse_nmap_xml((FIXTURES / "events" / "lab-scan.nmap.xml").read_bytes()):
        runtime.registry.observe(obs.model_copy(update={"ts": START}))
    yield runtime
    runtime.stop()


def node(rt: LabRuntime, ip: str) -> str:
    node_id = rt.registry.resolve(ip=ip)
    assert node_id is not None
    return node_id


def factor(decision: Any, name: str) -> Any:
    return next(f for f in decision.factors if f.name == name)


def test_gateway_kev_firmware_is_explained_with_graph_path(rt: LabRuntime) -> None:
    d = rt.risk.assess(node(rt, GATEWAY), now=START)
    assert d is not None
    vuln = factor(d, "vulnerable_service")
    intel = factor(d, "threat_intel")
    assert vuln.value > 0.5
    assert intel.value > 0.5
    kev = next(e for e in intel.evidence if e.kind == "kev")
    assert "CVE-2023-1389" in kev.summary
    assert [s.label for s in kev.path] == ["Device", "CPE", "Vulnerability"]
    assert kev.path[-1].name == "CVE-2023-1389"
    # Machine-readable explanation: contributions sum to the score.
    assert round(sum(c.contribution for c in d.contributions), 2) == d.score
    assert {c.factor for c in d.contributions} == {f.name for f in d.factors}
    assert d.level in {"high", "critical"}
    # Protected host: never recommended for quarantine.
    assert d.action in {"alert", "review_quarantine"}
    assert "CVE-2023-1389" in d.explanation
    assert d.explanation.startswith(d.level.upper())
    assert d.evidence_paths


def test_flood_drives_rate_factor_and_events(rt: LabRuntime) -> None:
    seen: list[Event] = []
    rt.bus.subscribe(seen.append)
    sim = TrafficSimulator(seed=3)
    esp = sim.device("esp32-node")
    events = [le.event for le in sim.normal(START, 3)]
    events += [le.event for le in sim.mqtt_flood(esp, START + timedelta(minutes=3), 1)]
    rt.pipeline.ingest(events)
    rt.pipeline.flush()
    history = rt.risk.history(node(rt, ESP))
    assert history, "risk was assessed automatically from ANOMALY_DETECTED"
    latest = history[0]
    rate = next(f for f in latest["factors"] if f["name"] == "rate_anomaly")
    assert rate["value"] >= 0.8
    assert any("mqtt_connect_flood" in str(e["detail"]) for e in rate["evidence"])
    assert latest["trigger"] == "ANOMALY_DETECTED"
    updates = [e for e in seen if e.type == "RISK_UPDATED" and e.node_id == node(rt, ESP)]
    assert updates
    assert updates[-1].payload["level"] == latest["level"]
    assert "contributions" in updates[-1].payload


def test_ioc_contact_correlates_threat(rt: LabRuntime) -> None:
    seen: list[Event] = []
    rt.bus.subscribe(seen.append)
    ev = TrafficEvent(
        ts=START + timedelta(seconds=10),
        src_mac="24:0a:c4:40:00:04",
        src_ip=ESP,
        dst_ip=FEODO_C2,
        dst_port=8080,
        proto="tcp",
    )
    rt.pipeline.ingest([ev])
    rt.pipeline.flush()
    d = rt.risk.assess(node(rt, ESP), now=START + timedelta(minutes=1))
    assert d is not None
    intel = factor(d, "threat_intel")
    ioc = next(e for e in intel.evidence if e.kind == "ioc")
    assert FEODO_C2 in ioc.summary
    assert "Emotet" in ioc.summary
    assert ioc.path is not None
    assert [s.via for s in ioc.path] == [None, "INDICATES"]
    assert intel.value == pytest.approx(0.48)  # Feodo offline C2: 80 x 0.6
    correlated = [e for e in seen if e.type == "THREAT_CORRELATED"]
    assert correlated
    assert correlated[0].node_id == node(rt, ESP)
    # Lab-internal destinations are never treated as IOCs.
    assert not any(e.kind == "ioc" and "192.168.50." in e.summary for e in intel.evidence)


def test_unknown_vs_approved_device(rt: LabRuntime) -> None:
    plug = node(rt, "192.168.50.23")
    before = rt.risk.assess(plug, now=START)
    rt.registry.approve(plug)
    after = rt.risk.assess(plug, now=START)
    assert before is not None
    assert after is not None
    assert factor(before, "unknown_device").value == 1.0
    assert factor(after, "unknown_device").value == 0.0
    assert after.score == before.score - 10.0


def test_single_source_cap(rt: LabRuntime) -> None:
    engine: RiskEngine = rt.risk
    device = rt.registry.get(node(rt, ESP))
    assert device is not None

    class StubGraph:
        def __init__(self, sources: list[str], conf: int) -> None:
            self.ind = {
                "id": "indicator--x",
                "confidence": conf,
                "sources": sources,
                "stale": False,
            }

        def indicators_for(self, ioc: str) -> list[dict[str, Any]]:
            return [self.ind] if ioc == "203.0.113.200" else []

        def related_threats(self, ioc: str, max_hops: int = 3) -> list[Any]:
            return []

    ev = TrafficEvent(
        ts=START, src_mac="24:0a:c4:40:00:04", src_ip=ESP, dst_ip="203.0.113.200", proto="tcp"
    )
    rt.pipeline.ingest([ev])
    rt.pipeline.flush()
    original = engine.graph
    try:
        engine.graph = StubGraph(["darkweb"], 58)  # type: ignore[assignment]
        capped = engine._threat_intel(device.node_id, device, [], START)
        engine.graph = StubGraph(["darkweb", "threatfox"], 58)  # type: ignore[assignment]
        corroborated = engine._threat_intel(device.node_id, device, [], START)
        engine.graph = StubGraph(["threatfox"], 90)  # type: ignore[assignment]
        confident = engine._threat_intel(device.node_id, device, [], START)
    finally:
        engine.graph = original
    assert capped.value == 0.5  # one unverified source can't exceed the cap
    assert corroborated.value == 0.58
    assert confident.value == 0.9


def test_unknown_node_and_no_ml(rt: LabRuntime) -> None:
    assert rt.risk.assess("dev-doesnotexist") is None
    d = rt.risk.assess(node(rt, GATEWAY))
    assert d is not None
    assert d.ml is None  # xgb_autotrain off in tests


@pytest.fixture(scope="module")
def xgb_model() -> Any:
    pytest.importorskip("shap")
    from app.behavior.config import load_behavior_config
    from app.core.config import BACKEND_ROOT
    from app.risk.dataset import scenario, windows
    from app.risk.ml import XgbModel

    cfg = load_behavior_config(BACKEND_ROOT / "config" / "behavior.yaml")
    data = [w for s in (101, 102, 103) for w in windows(scenario(s, 90), cfg)]
    return XgbModel.train([w.features for w in data], [w.label for w in data])


@pytest.mark.skipif(not SKLEARN, reason="needs the ML stack")
def test_ml_shap_explanation_is_consistent(xgb_model: Any, rt: LabRuntime, tmp_path: Path) -> None:
    from app.behavior.features import FEATURES
    from app.risk.ml import XgbModel

    flood = {f: 0.0 for f in FEATURES} | {
        "request_rate": 500.0,
        "mqtt_connect_rate": 500.0,
        "failed_attempts": 150.0,
        "bytes_mean": 110.0,
    }
    e = xgb_model.explain(flood, top=len(FEATURES))
    assert e.probability > 0.9
    logit = math.log(e.probability / (1 - e.probability))
    # SHAP additivity in log-odds space: base + sum(shap) = logit(p)
    assert e.base_value + sum(e.shap.values()) == pytest.approx(logit, abs=0.05)
    assert set(xgb_model.meta["global_importance"]) == set(FEATURES)
    # Signed JSON model round-trip.
    key = b"k" * 32
    xgb_model.save(tmp_path, key)
    loaded = XgbModel.load(tmp_path, key)
    assert loaded.predict_proba([flood])[0] == pytest.approx(e.probability, abs=1e-4)
    from app.behavior.anomaly import ModelIntegrityError

    with pytest.raises(ModelIntegrityError):
        XgbModel.load(tmp_path, b"x" * 32)
    # Attached to decisions, never changing them.
    rt.risk.ml = xgb_model
    sim = TrafficSimulator(seed=5)
    rt.pipeline.ingest([le.event for le in sim.normal(START, 2)])
    rt.pipeline.flush()
    d = rt.risk.assess(node(rt, ESP), now=START + timedelta(minutes=3))
    assert d is not None
    assert d.ml is not None
    assert 0 <= d.ml.probability <= 1
    assert d.ml.shap


def test_risk_api(make_settings: SettingsFactory) -> None:
    with TestClient(create_app(make_settings(protected_hosts=[GATEWAY]))) as client:
        rt = client.app.state.runtime  # type: ignore[attr-defined]
        for feed in ("cisa_kev", "nvd_cve"):
            rt.runner.run(feed)
        for obs in parse_nmap_xml((FIXTURES / "events" / "lab-scan.nmap.xml").read_bytes()):
            rt.registry.observe(obs.model_copy(update={"ts": START}))  # triggers assessment
        current = client.get("/api/risk").json()
        assert current[0]["score"] >= current[-1]["score"]  # sorted, highest first
        gw = rt.registry.resolve(ip=GATEWAY)
        detail = client.get(f"/api/risk/{gw}").json()
        assert detail["latest"]["level"] in {"high", "critical"}
        assert detail["latest"]["evidence_paths"]
        assert len(detail["history"]) >= 1
        assert client.get("/api/risk/dev-0000000000000000").status_code == 404
        model = client.get("/api/risk/model").json()
        assert model["linear"]["weights"]["threat_intel"] == 0.35
        assert model["ml"] is None
    with TestClient(create_app(make_settings(deployment="hosted"))) as hosted:
        assert hosted.get("/api/risk").status_code == 503
