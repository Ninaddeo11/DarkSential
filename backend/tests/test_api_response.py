from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.behavior.events import TrafficEvent
from app.core.config import BACKEND_ROOT
from app.detect.observations import Observation
from app.main import create_app
from app.simulation.traffic import TrafficSimulator
from tests.conftest import SettingsFactory

TOKEN = "admin-token-for-tests-0123456789abcdef"
JWT_SECRET = "jwt-secret-for-tests-0123456789abcdef"
T0 = datetime(2026, 10, 1, 9, tzinfo=UTC)


@pytest.fixture
def client(make_settings: SettingsFactory) -> Iterator[TestClient]:
    s = make_settings(
        admin_token=TOKEN, auth_jwt_secret=JWT_SECRET, protected_hosts=["192.168.50.1"]
    )
    with TestClient(create_app(s)) as c:
        yield c


def login(c: TestClient, secret: str = TOKEN) -> dict[str, str]:
    r = c.post("/api/auth/login", json={"secret": secret})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def auth(client: TestClient) -> dict[str, str]:
    return login(client)


def node(c: TestClient, mac: str, ip: str) -> str:
    rt = c.app.state.runtime  # type: ignore[attr-defined]
    view = rt.registry.observe(Observation(source="arp", ts=T0, mac=mac, ip=ip))
    assert view is not None
    return str(view.node_id)


def test_mutations_require_valid_bearer_token(client: TestClient, auth: dict[str, str]) -> None:
    n = node(client, "24:0a:c4:40:00:04", "192.168.50.24")
    body = {"node_id": n, "reason": "suspicious"}
    assert client.post("/api/quarantines", json=body).status_code == 401
    bad = client.post("/api/quarantines", json=body, headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401
    assert bad.headers["www-authenticate"] == "Bearer"
    basic = client.post("/api/quarantines", json=body, headers={"Authorization": f"Basic {TOKEN}"})
    assert basic.status_code == 401
    # The long-lived admin secret itself is not a bearer token: log in first.
    raw = client.post("/api/quarantines", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert raw.status_code == 401
    ok = client.post("/api/quarantines", json=body, headers=auth)
    assert ok.status_code == 201
    assert ok.json()["actor"] == "api:admin"
    assert ok.json()["reason"] == "manual: suspicious"


def test_mutations_disabled_without_auth(make_settings: SettingsFactory) -> None:
    with TestClient(create_app(make_settings())) as c:
        n = node(c, "24:0a:c4:40:00:04", "192.168.50.24")
        r = c.post("/api/quarantines", json={"node_id": n, "reason": "x y z"})
        assert r.status_code == 403
        assert "DSN_AUTH_JWT_SECRET" in r.json()["detail"]
        assert c.get("/api/quarantines").status_code == 200  # reads stay available


def test_quarantine_release_approve_audit(client: TestClient, auth: dict[str, str]) -> None:
    n = node(client, "24:0a:c4:40:00:04", "192.168.50.24")
    gw = node(client, "50:c7:bf:00:00:01", "192.168.50.1")
    refused = client.post(
        "/api/quarantines", json={"node_id": gw, "reason": "test it"}, headers=auth
    )
    assert refused.status_code == 409
    assert "protected host" in refused.json()["detail"]
    assert (
        client.post(
            "/api/quarantines",
            json={"node_id": "dev-0000000000000000", "reason": "abc"},
            headers=auth,
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/quarantines", json={"node_id": "bad", "reason": "abc"}, headers=auth
        ).status_code
        == 422
    )
    q = client.post(
        "/api/quarantines",
        json={"node_id": n, "reason": "manual check", "minutes": 15},
        headers=auth,
    ).json()
    active = client.get("/api/quarantines", params={"status": "active"}).json()
    assert [a["id"] for a in active] == [q["id"]]
    released = client.post(
        f"/api/quarantines/{q['id']}/release", json={"reason": "verified clean"}, headers=auth
    )
    assert released.json()["status"] == "released"
    assert (
        client.post(
            "/api/quarantines/999/release", json={"reason": "abc"}, headers=auth
        ).status_code
        == 404
    )
    approved = client.post(f"/api/devices/{n}/approve", headers=auth)
    assert approved.json()["trust"] == "approved"
    assert client.post("/api/devices/dev-0000000000000000/approve", headers=auth).status_code == 404
    audit = client.get("/api/audit", params={"limit": 50}).json()
    actions = [(a["action"], a["outcome"], a["actor"]) for a in audit]
    assert ("approve", "ok", "api:admin") in actions
    assert ("quarantine", "refused", "api:admin") in actions
    assert ("release", "dry_run", "api:admin") in actions
    assert client.get("/api/audit", params={"node_id": n}).json()
    verify = client.get("/api/audit/verify").json()
    assert verify["ok"] is True
    assert verify["entries"] >= 4
    health = client.get("/api/health/ready").json()["checks"]
    assert health["response"]["status"] == "ok"
    assert "driver=dryrun" in health["response"]["detail"]


def test_hosted_mode_has_no_response_api(make_settings: SettingsFactory) -> None:
    s = make_settings(deployment="hosted", admin_token=TOKEN, auth_jwt_secret=JWT_SECRET)
    with TestClient(create_app(s)) as c:
        auth = login(c)
        assert c.get("/api/quarantines").status_code == 503
        assert (
            c.post(
                "/api/quarantines",
                json={"node_id": "dev-0000000000000000", "reason": "abc"},
                headers=auth,
            ).status_code
            == 503
        )


def test_risk_to_auto_quarantine_end_to_end(make_settings: SettingsFactory, tmp_path: Path) -> None:
    """Flood + C2 contact -> CRITICAL (threshold lowered to 40) -> auto quarantine -> recovery."""
    cfg = yaml.safe_load((BACKEND_ROOT / "config" / "risk.yaml").read_text(encoding="utf-8"))
    cfg["thresholds"] = {"low": 0, "medium": 20, "high": 30, "critical": 40}
    risk_path = tmp_path / "risk.yaml"
    risk_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    s = make_settings(risk_config_path=risk_path, quarantine_minutes=10)
    with TestClient(create_app(s)) as c:
        rt = c.app.state.runtime  # type: ignore[attr-defined]
        rt.runner.run("feodo")
        sim = TrafficSimulator(seed=11)
        esp = sim.device("esp32-node")
        events = [le.event for le in sim.mqtt_flood(esp, T0, minutes=1)]
        events.append(
            TrafficEvent(
                ts=T0 + timedelta(seconds=20),
                src_mac=esp.mac,
                src_ip=esp.ip,
                dst_ip="162.243.103.246",
                dst_port=8080,
                proto="tcp",
            )
        )
        rt.pipeline.ingest(events)
        rt.pipeline.flush()
        active = c.get("/api/quarantines", params={"status": "active"}).json()
        assert len(active) == 1
        q = active[0]
        assert q["actor"] == "system:risk-engine"
        assert q["evidence"]["level"] == "critical"
        assert "Emotet" in q["evidence"]["explanation"]
        types = [e["type"] for e in c.get("/api/events", params={"limit": 1000}).json()]
        assert (
            types.index("RISK_UPDATED")
            < types.index("QUARANTINE_STARTED")
            < types.index("QUARANTINE_COMPLETED")
        )
        # Auto-recovery after the window (sweep path; the scheduler job does the same).
        assert (
            rt.response.expire_due(
                datetime.fromisoformat(str(q["expires_at"])) + timedelta(seconds=1)
            )
            == 1
        )
        types = [e["type"] for e in c.get("/api/events", params={"limit": 1000}).json()]
        assert "RECOVERY_STARTED" in types
        assert types[-1] == "DEVICE_RESTORED" or "DEVICE_RESTORED" in types
        assert c.get("/api/audit/verify").json()["ok"] is True
