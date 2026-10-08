"""End-to-end against a REAL Mosquitto (TLS, passwords, ACLs, broker log).

Run with ``python scripts/tasks.py docker-test-mqtt`` (or CI job ``iot``). It
needs DSN_TEST_MQTT_DIR (provisioning output), DSN_TEST_MQTT_HOST/PORT and
DSN_TEST_MQTT_LOG (the broker's log file, shared with this container).
"""

from __future__ import annotations

import json
import os
import ssl
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from app.feeds.config import load_feeds_config
from app.mqtt.commands import COMMAND_TOPIC, verify
from app.runtime import LabRuntime
from tests.conftest import SettingsFactory

# Read at import: the autouse fixture strips DSN_* variables before tests run.
MQTT_DIR = os.environ.get("DSN_TEST_MQTT_DIR")
HOST = os.environ.get("DSN_TEST_MQTT_HOST", "mosquitto")
PORT = int(os.environ.get("DSN_TEST_MQTT_PORT", "8883"))
LOG = os.environ.get("DSN_TEST_MQTT_LOG")

pytestmark = [
    pytest.mark.mqtt,
    pytest.mark.skipif(not (MQTT_DIR and LOG), reason="needs a real broker (docker-test-mqtt)"),
]


def wait_for(cond: Callable[[], bool], timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.1)
    return False


def creds() -> dict[str, Any]:
    return dict(json.loads((Path(str(MQTT_DIR)) / "credentials.json").read_text()))


def paho(user: str, password: str, client_id: str) -> tuple[Any, dict[str, Any]]:
    import paho.mqtt.client as mqtt
    from paho.mqtt.enums import CallbackAPIVersion

    state: dict[str, Any] = {"rc": None, "msgs": []}
    c = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id)
    c.username_pw_set(user, password)
    c.tls_set(ca_certs=str(Path(str(MQTT_DIR)) / "certs" / "ca.crt"), cert_reqs=ssl.CERT_REQUIRED)
    c.on_connect = lambda cl, u, f, rc, p: state.__setitem__("rc", str(rc))
    c.on_message = lambda cl, u, m: state["msgs"].append((m.topic, bytes(m.payload)))
    c.connect(HOST, PORT, keepalive=30)
    c.loop_start()
    assert wait_for(lambda: state["rc"] is not None)
    return c, state


@pytest.fixture
def rt(make_settings: SettingsFactory) -> Iterator[LabRuntime]:
    c = creds()
    s = make_settings(
        mqtt_host=HOST,
        mqtt_port=PORT,
        mqtt_username="dsn-backend",
        mqtt_password=c["users"]["dsn-backend"],
        mqtt_ca_file=str(Path(str(MQTT_DIR)) / "certs" / "ca.crt"),
        mqtt_command_key=c["command_key"],
        mqtt_broker_log=Path(str(LOG)),
    )
    runtime = LabRuntime.build(s, load_feeds_config(s.feeds_config_path))
    runtime.start()
    yield runtime
    runtime.stop()


def test_signed_command_ack_telemetry_and_acl(rt: LabRuntime) -> None:
    c = creds()
    users, key = c["users"], c["command_key"].encode()
    assert wait_for(lambda: bool(rt.publisher.connected()))  # type: ignore[attr-defined]

    # Simulated status node: verify signature, then ack (what the firmware does).
    status, st = paho("status-node", users["status-node"], "status-node")
    assert st["rc"] == "Success"

    def on_cmd(client: Any, userdata: Any, msg: Any) -> None:
        payload = json.loads(msg.payload)
        ok = verify(payload, key)
        client.publish(
            "dsn/ack/status-node",
            json.dumps({"id": payload["id"], "status": "ok" if ok else "bad_sig"}),
            qos=1,
        )
        st["msgs"].append((msg.topic, payload))

    status.on_message = on_cmd
    status.subscribe(COMMAND_TOPIC, qos=1)
    time.sleep(0.5)

    cmd = rt.response.commander.send("ALERT", "dev-1234567890abcdef", "high")
    assert wait_for(
        lambda: any(isinstance(m[1], dict) and m[1]["id"] == cmd["id"] for m in st["msgs"])
    )
    assert wait_for(lambda: any(e["action"] == "mqtt_ack" for e in rt.audit.entries(10)))
    ack = next(e for e in rt.audit.entries(10) if e["action"] == "mqtt_ack")
    assert ack["details"]["status"] == "ok"
    assert ack["details"]["command_id"] == cmd["id"]

    # Device telemetry -> registry (ACL-authenticated identity from the topic).
    dev, _dv = paho("esp32-node", users["esp32-node"], "esp32-node")
    dev.publish(
        "dsn/telemetry/esp32-node",
        json.dumps(
            {
                "v": 1,
                "mac": "24:0a:c4:40:00:04",
                "ip": "192.168.50.24",
                "fw": "0.1.0",
                "rssi": -58,
                "state": "NORMAL",
                "seq": 1,
            }
        ),
        qos=1,
    )
    assert wait_for(lambda: rt.registry.resolve(mac="24:0a:c4:40:00:04") is not None)
    node = rt.registry.resolve(mac="24:0a:c4:40:00:04")
    assert node is not None
    device = rt.registry.get(node)
    assert device is not None
    assert device.attributes["mqtt_user"] == "esp32-node"
    assert "telemetry" in device.sources

    # A device can't publish commands or other devices' telemetry (ACL drop).
    before = len(st["msgs"])
    dev.publish(COMMAND_TOPIC, json.dumps({"cmd": "RECOVER"}), qos=1)
    dev.publish("dsn/telemetry/rogue-sensor", json.dumps({"v": 1}), qos=1)
    time.sleep(1.5)
    assert len(st["msgs"]) == before

    # Rogue client: wildcard subscription + command publish + bad passwords.
    rogue, rg = paho("rogue-sensor", users["rogue-sensor"], "rogue-sensor")
    rogue.subscribe("#", qos=0)
    time.sleep(0.5)
    rogue.publish(COMMAND_TOPIC, json.dumps({"cmd": "NORMAL"}), qos=1)
    rt.response.commander.send("NORMAL")  # a real command flows while rogue listens to '#'
    for i in range(3):
        bad, br = paho("esp32-node", "wrong-password", f"bad-{i}")
        assert br["rc"] == "Not authorized"
        bad.loop_stop()
    # Broker log -> tailer (1 s poll) -> pipeline. Poll rather than sleep a fixed
    # time: on a slow CI runner the broker flushes its log late.
    results: list[Any] = []

    def broker_log_seen() -> bool:
        results.extend(rt.pipeline.flush())
        hits = {h.rule_id for r in results for h in r.rule_hits}
        failed = sum(r.features.get("failed_attempts", 0) for r in results)
        return {"mqtt_wildcard_subscription", "mqtt_restricted_publish"} <= hits and failed >= 3

    seen = wait_for(broker_log_seen, timeout=20.0)
    assert rg["msgs"] == []  # '#' grants nothing: ACL default deny
    hits = {h.rule_id for r in results for h in r.rule_hits}
    assert "mqtt_wildcard_subscription" in hits
    assert "mqtt_restricted_publish" in hits
    failed = sum(r.features.get("failed_attempts", 0) for r in results)
    assert failed >= 3  # the refused CONNECTs were seen in the broker log
    assert seen
    for client in (status, dev, rogue):
        client.loop_stop()
        client.disconnect()
