from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.health import CheckResult
from app.main import create_app
from tests.conftest import SettingsFactory, requires_spacy


@pytest.fixture
def lab(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as client:
        runtime = client.app.state.runtime  # type: ignore[attr-defined]
        for name in ("mitre_attack", "cisa_kev", "nvd_cve", "feodo", "threatfox"):
            runtime.runner.run(name)
        yield client


def test_feeds_status_lab(lab: TestClient) -> None:
    body = lab.get("/api/feeds/status").json()
    assert body["scheduler"] == "disabled"
    assert body["graph_backend"] == "memory"
    feeds = {f["name"]: f for f in body["feeds"]}
    assert set(feeds) == {
        "cisa_kev",
        "nvd_cve",
        "mitre_attack",
        "urlhaus",
        "threatfox",
        "feodo",
        "darkweb",
    }
    assert feeds["cisa_kev"]["last_run"]["status"] == "success"
    assert feeds["cisa_kev"]["mode"] == "mock"
    assert feeds["urlhaus"]["last_run"] is None


def test_feeds_status_with_scheduler(make_settings: SettingsFactory) -> None:
    with TestClient(create_app(make_settings(scheduler_enabled=True))) as client:
        body = client.get("/api/feeds/status").json()
    assert body["scheduler"] == "running"
    assert all(f["next_run_at"] for f in body["feeds"])


def test_related_threats_endpoint(lab: TestClient) -> None:
    resp = lab.get("/api/intel/related-threats", params={"ioc": "162.243.103[.]246"})
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()}
    assert "Emotet" in names
    assert (
        lab.get("/api/intel/related-threats", params={"ioc": "x", "max_hops": 9}).status_code == 422
    )
    assert lab.get("/api/intel/related-threats", params={"ioc": " "}).status_code == 422


def test_cves_endpoint(lab: TestClient) -> None:
    cpe = "cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.1:*:*:*:*:*:*:*"
    data = lab.get("/api/intel/cves", params={"cpe": cpe}).json()
    assert data[0]["cve"] == "CVE-2023-1389"
    assert data[0]["kev"] is True
    bad = lab.get("/api/intel/cves", params={"cpe": "cpe:/o:old:format"})
    assert bad.status_code == 422


def test_techniques_and_counts(lab: TestClient) -> None:
    runtime = lab.app.state.runtime  # type: ignore[attr-defined]
    runtime.graph.link_rule("r1", ["T1498"], "test")
    assert (
        lab.get("/api/intel/techniques", params={"rule_id": "r1"}).json()[0]["external_id"]
        == "T1498"
    )
    counts = lab.get("/api/intel/graph/counts").json()
    assert counts["Vulnerability"] >= 5
    assert counts["AttackPattern"] > 10


@requires_spacy
def test_extract_endpoint(lab: TestClient) -> None:
    resp = lab.post("/api/intel/extract", json={"text": "CVE-2023-1389 by QBot via T1190"})
    types = {(e["type"], e["value"]) for e in resp.json()["entities"]}
    assert ("CVE", "CVE-2023-1389") in types
    assert ("MALWARE", "QakBot") in types
    assert ("ATTACK_TECHNIQUE", "T1190") in types


def test_extract_limits(lab: TestClient) -> None:
    assert lab.post("/api/intel/extract", json={"text": ""}).status_code == 422
    assert lab.post("/api/intel/extract", json={"text": "x" * 20_001}).status_code == 422


def test_hosted_mode_has_no_graph(make_settings: SettingsFactory) -> None:
    with TestClient(create_app(make_settings(deployment="hosted"))) as client:
        assert client.app.state.runtime is None  # type: ignore[attr-defined]
        status = client.get("/api/feeds/status").json()
        assert status["scheduler"] == "unavailable_hosted"
        assert status["graph_backend"] == "none"
        assert {f["mode"] for f in status["feeds"]} == {"mock"}
        resp = client.get("/api/intel/related-threats", params={"ioc": "1.2.3.4"})
        assert resp.status_code == 503
        checks = client.get("/api/health/ready").json()["checks"]
        assert checks["database"]["status"] == "not_configured"
        assert checks["graph"]["status"] == "not_configured"


def test_readiness_errors_when_graph_down(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        runtime = client.app.state.runtime  # type: ignore[attr-defined]

        def down() -> None:
            raise ConnectionError("bolt://neo4j:secret@host")

        runtime.graph.ping = down
        resp = client.get("/api/health/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["graph"] == {
        "status": "error",
        "detail": "ConnectionError",
        "latency_ms": resp.json()["checks"]["graph"]["latency_ms"],
    }
    assert "secret" not in resp.text


def test_runtime_survives_schema_failure(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    from app.graph.memory import InMemoryGraphStore
    from app.runtime import LabRuntime

    class Broken(InMemoryGraphStore):
        def ensure_schema(self) -> None:
            raise ConnectionError("down")

    rt = LabRuntime.build(settings, load(settings), graph=Broken())
    rt.start()
    rt.stop()
    assert "graph schema setup failed" in caplog.text


def load(settings: Settings):  # type: ignore[no-untyped-def]
    from app.feeds.config import load_feeds_config

    return load_feeds_config(settings.feeds_config_path)


def test_graph_check_ok_for_neo4j_backend(settings: Settings) -> None:
    import asyncio

    from app.graph.memory import InMemoryGraphStore
    from app.runtime import LabRuntime

    class FakeNeo(InMemoryGraphStore):
        pass

    rt = LabRuntime.build(settings, load(settings), graph=FakeNeo())
    rt.__class__ = type("R", (LabRuntime,), {"graph_backend": property(lambda self: "neo4j")})
    assert asyncio.run(rt.check_graph()) == CheckResult(status="ok")
    rt.stop()
