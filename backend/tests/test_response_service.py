from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from app.core.events import Event
from app.detect.observations import Observation
from app.feeds.config import load_feeds_config
from app.mqtt.commands import ACK_TOPIC, COMMAND_TOPIC, NullPublisher, StatusNodeCommander, verify
from app.response.audit import AuditLog
from app.response.drivers import DriverError, NftablesDriver
from app.response.service import QuarantineRefused
from app.runtime import LabRuntime
from tests.conftest import SettingsFactory
from tests.test_response_drivers import FakeNft

T0 = datetime(2026, 10, 1, 9, tzinfo=UTC)
CMD_KEY = "status-node-command-key-0123456789abcdef"


@pytest.fixture
def rt(make_settings: SettingsFactory) -> Iterator[LabRuntime]:
    s = make_settings(
        protected_hosts=["192.168.50.1"], mqtt_command_key=CMD_KEY, max_active_quarantines=2
    )
    runtime = LabRuntime.build(s, load_feeds_config(s.feeds_config_path))
    runtime.start()
    yield runtime
    runtime.stop()


def device(rt: LabRuntime, mac: str, ip: str) -> str:
    view = rt.registry.observe(Observation(source="arp", ts=T0, mac=mac, ip=ip))
    assert view is not None
    return view.node_id


def collect(rt: LabRuntime) -> list[Event]:
    events: list[Event] = []
    rt.bus.subscribe(events.append)
    return events


def test_quarantine_and_release_flow(rt: LabRuntime) -> None:
    events = collect(rt)
    node = device(rt, "24:0a:c4:40:00:04", "192.168.50.24")
    q = rt.response.quarantine(node, "test", actor="cli", minutes=10, now=T0)
    assert q["status"] == "active"
    assert q["dry_run"] is True
    assert q["expires_at"] == T0 + timedelta(minutes=10)
    assert rt.response.driver.active() == {"192.168.50.24"}
    types = [e.type for e in events if e.node_id == node]
    assert types[-2:] == ["QUARANTINE_STARTED", "QUARANTINE_COMPLETED"]
    # Idempotent re-quarantine extends instead of duplicating.
    again = rt.response.quarantine(node, "again", actor="cli", minutes=30, now=T0)
    assert again["id"] == q["id"]
    assert again["expires_at"] == T0 + timedelta(minutes=30)
    released = rt.response.release(
        q["id"], actor="cli", reason="done", now=T0 + timedelta(minutes=5)
    )
    assert released["status"] == "released"
    assert released["released_by"] == "cli"
    assert rt.response.release(q["id"], actor="cli", reason="again")["status"] == "released"
    assert rt.response.driver.active() == set()
    assert [e.type for e in events if e.node_id == node][-2:] == [
        "RECOVERY_STARTED",
        "DEVICE_RESTORED",
    ]
    actions = [(e["action"], e["outcome"]) for e in reversed(rt.audit.entries())]
    assert ("quarantine", "dry_run") in actions
    assert ("extend", "ok") in actions
    assert ("release", "dry_run") in actions
    assert rt.audit.verify_chain().ok
    # Status-node commands were signed and sent.
    pub = rt.response.commander.publisher
    assert isinstance(pub, NullPublisher)
    cmds = [json.loads(p) for topic, p in pub.sent if topic == COMMAND_TOPIC]
    assert [c["cmd"] for c in cmds] == ["QUARANTINE", "RECOVER"]
    assert all(verify(c, CMD_KEY.encode()) for c in cmds)


@pytest.mark.parametrize(
    ("ip", "fragment"),
    [("192.168.50.1", "protected host"), ("10.9.9.9", "outside the lab")],
)
def test_refusals_are_audited(rt: LabRuntime, ip: str, fragment: str) -> None:
    events = collect(rt)
    node = device(rt, "44:19:b6:10:00:01", ip)
    with pytest.raises(QuarantineRefused, match=fragment):
        rt.response.quarantine(node, "x", actor="cli", now=T0)
    assert rt.response.driver.active() == set()
    entry = rt.audit.entries(limit=1)[0]
    assert (entry["action"], entry["outcome"]) == ("quarantine", "refused")
    assert fragment in entry["details"]["refusal"]
    refused = [e for e in events if e.type == "QUARANTINE_COMPLETED"]
    assert refused[-1].payload["ok"] is False


def test_concurrent_limit_and_missing_ip(rt: LabRuntime) -> None:
    nodes = [device(rt, f"24:0a:c4:40:00:1{i}", f"192.168.50.{40 + i}") for i in range(3)]
    for n in nodes[:2]:
        rt.response.quarantine(n, "x", actor="cli", now=T0)
    with pytest.raises(QuarantineRefused, match="limit of 2"):
        rt.response.quarantine(nodes[2], "x", actor="cli", now=T0)
    no_ip = rt.registry.observe(Observation(source="ble", ts=T0, mac="c0:ff:ee:00:00:01"))
    assert no_ip is not None
    with pytest.raises(QuarantineRefused, match="no known IP"):
        rt.response.quarantine(no_ip.node_id, "x", actor="cli", now=T0)
    with pytest.raises(KeyError):
        rt.response.quarantine("dev-0000000000000000", "x", actor="cli")
    with pytest.raises(KeyError):
        rt.response.release(9999, actor="cli", reason="x")
    with pytest.raises(KeyError):
        rt.response.release_node("dev-0000000000000000", actor="cli", reason="x")


def test_expiry_and_reconcile(rt: LabRuntime) -> None:
    a = device(rt, "24:0a:c4:40:00:21", "192.168.50.61")
    b = device(rt, "24:0a:c4:40:00:22", "192.168.50.62")
    rt.response.quarantine(a, "short", actor="cli", minutes=1, now=T0)
    rt.response.quarantine(b, "long", actor="cli", minutes=60, now=T0)
    # Drift: someone removed b by hand and added a stray element.
    rt.response.driver.release("192.168.50.62")
    rt.response.driver.quarantine("192.168.50.99")
    diff = rt.response.reconcile(now=T0 + timedelta(minutes=2))
    assert diff["expired_released"] == 1  # a expired
    assert diff["desired"] == ["192.168.50.62"]
    assert diff["in_sync"] is True
    assert rt.response.driver.active() == {"192.168.50.62"}
    assert rt.response.expire_due(T0 + timedelta(minutes=61)) == 1
    assert rt.response.list(status="active") == []
    assert rt.audit.verify_chain().ok


def test_driver_failure_marks_failed(rt: LabRuntime) -> None:
    node = device(rt, "24:0a:c4:40:00:31", "192.168.50.71")

    class Broken(NftablesDriver):
        def quarantine(self, ip: str) -> None:
            raise DriverError("nft: permission denied")

    rt.response.driver = Broken(FakeNft())
    with pytest.raises(DriverError):
        rt.response.quarantine(node, "x", actor="cli", now=T0)
    assert rt.response.list()[0]["status"] == "failed"
    assert rt.audit.entries(limit=1)[0]["outcome"] == "failed"


def test_auto_quarantine_and_alert_policy(rt: LabRuntime) -> None:
    node = device(rt, "24:0a:c4:40:00:41", "192.168.50.81")
    pub = rt.response.commander.publisher
    assert isinstance(pub, NullPublisher)
    rt.bus.emit("RISK_UPDATED", node, ts=T0, action="review_quarantine", level="high", score=60)
    assert rt.response.list(status="active") == []
    assert json.loads(pub.sent[-1][1])["cmd"] == "ALERT"
    rt.bus.emit(
        "RISK_UPDATED",
        node,
        ts=T0,
        action="quarantine",
        level="critical",
        score=88,
        explanation="CRITICAL",
        contributions=[],
    )
    active = rt.response.list(status="active")
    assert len(active) == 1
    assert active[0]["actor"] == "system:risk-engine"
    assert active[0]["evidence"]["score"] == 88
    rt.response.settings = rt.response.settings.model_copy(update={"auto_quarantine": False})
    other = device(rt, "24:0a:c4:40:00:42", "192.168.50.82")
    rt.bus.emit("RISK_UPDATED", other, ts=T0, action="quarantine", level="critical", score=90)
    assert len(rt.response.list(status="active")) == 1


def test_acks_are_audited(rt: LabRuntime) -> None:
    cmd = rt.response.commander.send("ALERT", "dev-1234567890abcdef", "high")
    rt.response.on_ack(json.dumps({"id": cmd["id"], "status": "ok"}).encode())
    rt.response.on_ack(b"not json")
    rt.response.on_ack(json.dumps({"id": "unknown"}).encode())
    entry = rt.audit.entries(limit=1)[0]
    assert (entry["action"], entry["actor"]) == ("mqtt_ack", "status-node")
    assert entry["details"]["cmd"] == "ALERT"
    assert ACK_TOPIC == "dsn/ack/status-node"


def test_audit_chain_detects_tampering(rt: LabRuntime) -> None:
    for i in range(5):
        rt.audit.record("tester", "note", details={"i": i})
    assert rt.audit.verify_chain().ok
    with rt.engine.begin() as conn:
        conn.execute(text("UPDATE audit_log SET details = '{\"i\": 99}' WHERE id = 3"))
    status = rt.audit.verify_chain()
    assert not status.ok
    assert status.first_bad_id == 3


def test_audit_chain_detects_deletion(rt: LabRuntime) -> None:
    for i in range(4):
        rt.audit.record("tester", "note", details={"i": i})
    with rt.engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_log WHERE id = 2"))
    assert rt.audit.verify_chain().first_bad_id == 3


def test_audit_concurrent_writers_keep_chain(rt: LabRuntime) -> None:
    log: AuditLog = rt.audit
    threads = [
        threading.Thread(target=lambda: [log.record("t", "note") for _ in range(20)])
        for _ in range(5)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    status = log.verify_chain()
    assert status.ok
    assert status.entries >= 100


def test_commander_signing_and_publish_failure() -> None:
    class Exploding(NullPublisher):
        def publish(self, topic: str, payload: str, qos: int = 1) -> None:
            raise OSError("broker down")

    key = b"k" * 32
    cmd = StatusNodeCommander(Exploding(), key).send("QUARANTINE", "dev-1", "critical")
    assert cmd["publish_error"] is True  # never raises into enforcement
    tampered: dict[str, Any] = {**cmd, "cmd": "RECOVER"}
    assert not verify(tampered, key)
    unsigned = StatusNodeCommander(NullPublisher(), None).send("NORMAL")
    assert "sig" not in unsigned


def test_recovery_job_scheduled_persistently(
    make_settings: SettingsFactory, tmp_path: Path
) -> None:
    s = make_settings(scheduler_enabled=True)
    rt = LabRuntime.build(s, load_feeds_config(s.feeds_config_path))
    rt.start()
    try:
        node = device(rt, "24:0a:c4:40:00:51", "192.168.50.91")
        q = rt.response.quarantine(node, "x", actor="cli", minutes=5)
        assert rt.scheduler is not None
        assert f"recover:{q['id']}" in rt.scheduler.job_ids()
        assert "job:response_sweep" in rt.scheduler.job_ids()
        assert "job:risk_rescore" in rt.scheduler.job_ids()
        from app.feeds import jobs

        jobs.run_recovery_job(q["id"])  # what the scheduler calls at expiry
        assert rt.response.get(q["id"])["status"] == "released"
        assert f"recover:{q['id']}" not in rt.scheduler.job_ids()
        assert rt.rescore_all() >= 1
    finally:
        rt.stop()
