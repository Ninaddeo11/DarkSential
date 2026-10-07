from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.behavior.events import TrafficEvent
from app.detect.observations import Observation
from app.mqtt.brokerlog import BrokerLogParser, BrokerLogTailer, tail_once
from app.mqtt.commands import sign, signing_string, verify
from app.mqtt.telemetry import TelemetryConsumer
from tests.conftest import FIXTURES

ROOT = Path(__file__).resolve().parents[2]
LOG = FIXTURES / "events" / "mosquitto.sample.log"

# Shared with firmware/esp32-node/test/test_native/test_signing.cpp: both sides
# must produce exactly this signature, or the status node rejects every command.
VECTOR = {
    "id": "4a0f7c4e-1111-4222-8333-444455556666",
    "ts": 1790000000,
    "cmd": "QUARANTINE",
    "node_id": "dev-8b32829a42842662",
    "level": "critical",
    "ttl": 60,
}
VECTOR_KEY = b"status-node-command-key-0123456789abcdef"
VECTOR_SIG = "80bf20325c28621746d8e521ea080dae4a88304630db3a9ba85f661bf60681e3"


def test_signing_vector_matches_firmware() -> None:
    assert signing_string(VECTOR) == (
        b"4a0f7c4e-1111-4222-8333-444455556666|1790000000|QUARANTINE|"
        b"dev-8b32829a42842662|critical|60"
    )
    assert sign(VECTOR, VECTOR_KEY) == VECTOR_SIG
    assert verify({**VECTOR, "sig": VECTOR_SIG}, VECTOR_KEY)
    assert not verify({**VECTOR, "sig": VECTOR_SIG, "ttl": 61}, VECTOR_KEY)
    assert not verify({**VECTOR, "node_id": "x|y", "sig": VECTOR_SIG}, VECTOR_KEY)


# --- broker log ----------------------------------------------------------------------


def test_parse_real_mosquitto_log() -> None:
    events = tail_once(LOG, BrokerLogParser("192.168.50.2", frozenset({"dsn-backend"})))
    kinds = Counter((e.mqtt.packet if e.mqtt else None, e.ok) for e in events)
    assert kinds[("CONNECT", True)] == 3  # status-node, esp32-node, rogue-sensor
    assert kinds[("CONNECT", False)] == 6  # bad password + anonymous retries
    wildcard = [
        e for e in events if e.mqtt and e.mqtt.packet == "SUBSCRIBE" and e.mqtt.topic == "#"
    ]
    assert len(wildcard) == 1
    assert wildcard[0].mqtt is not None
    assert wildcard[0].mqtt.client_id == "rogue-sensor"
    denied = {
        (e.mqtt.client_id, e.mqtt.topic)
        for e in events
        if e.mqtt and e.mqtt.packet == "PUBLISH" and e.ok is False
    }
    assert denied == {
        ("esp32-node", "dsn/telemetry/rogue-sensor"),
        ("rogue-sensor", "dsn/cmd/status-node"),
    }
    # The backend's own wildcard subscriptions / command publishes are excluded.
    assert not any(e.mqtt and e.mqtt.client_id == "dsn-backend" for e in events)
    assert all(e.dst_ip == "192.168.50.2" and e.dst_port == 8883 for e in events)
    assert all(ipaddress.ip_address(e.src_ip or "") for e in events)


def test_parser_without_ignore_sees_backend() -> None:
    events = tail_once(LOG, BrokerLogParser())
    assert any(
        e.mqtt and e.mqtt.client_id == "dsn-backend" and e.mqtt.topic == "dsn/telemetry/#"
        for e in events
    )


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        "2026-10-07T15:29:23: Received PUBLISH from ghost (d0, q1, r0, m1, 'x', ... (1 bytes))",
        "2026-10-07T15:29:23: unknown-client 0 #",
        "2026-13-40T99:99:99: New client connected from 1.2.3.4:1 as x (p2, c1, k30, u'x').",
    ],
)
def test_malformed_lines_are_skipped(line: str) -> None:
    assert BrokerLogParser().parse(line) is None


def test_overlong_username_falls_back_to_client_id() -> None:
    ev = BrokerLogParser().parse(
        "2026-10-07T15:29:23: New client connected from 1.2.3.4:1 as x (p2, c1, k30, u'"
        + "y" * 70
        + "')."
    )
    assert ev is not None
    assert ev.mqtt is not None
    assert ev.mqtt.client_id == "x"


def test_tailer_follows_appends_and_rotation(tmp_path: Path) -> None:
    path = tmp_path / "mosquitto.log"
    lines = LOG.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text("".join(lines[:5]), encoding="utf-8")
    got: list[TrafficEvent] = []
    tailer = BrokerLogTailer(
        path, BrokerLogParser(), got.extend, poll_seconds=0.05, from_start=True
    )
    tailer.start()
    try:
        deadline = time.time() + 5
        with path.open("a", encoding="utf-8") as fh:
            fh.writelines(lines[5:])
        while time.time() < deadline and len(got) < 10:
            time.sleep(0.05)
        first = len(got)
        assert first >= 10
        # Rotated: a shorter file with fresh events (connect + subscribe lines).
        path.write_text(
            "".join(ln for ln in lines if "New client connected" in ln), encoding="utf-8"
        )
        while time.time() < deadline and len(got) == first:
            time.sleep(0.05)
        assert len(got) > first
    finally:
        tailer.stop()


# --- telemetry -----------------------------------------------------------------------


def test_telemetry_consumer() -> None:
    seen: list[Observation] = []
    events: list[TrafficEvent] = []
    consumer = TelemetryConsumer(
        seen.append,
        events.extend,
        broker_ip="192.168.50.2",
        clock=lambda: datetime(2026, 10, 1, tzinfo=UTC),
    )
    payload = json.dumps(
        {
            "v": 1,
            "mac": "24:0a:c4:40:00:04",
            "ip": "192.168.50.24",
            "fw": "0.1.0",
            "uptime_s": 99,
            "rssi": -61,
            "heap": 180000,
            "state": "NORMAL",
            "seq": 7,
            "extra": "ignored",
        }
    ).encode()
    assert consumer.handle("dsn/telemetry/esp32-node", payload)
    obs = seen[0]
    assert (obs.source, obs.mac, obs.ip, obs.hostname) == (
        "telemetry",
        "24:0a:c4:40:00:04",
        "192.168.50.24",
        "esp32-node",
    )
    assert obs.attributes["mqtt_user"] == "esp32-node"
    assert obs.attributes["rssi"] == -61
    assert events[0].mqtt is not None
    assert events[0].mqtt.topic == "dsn/telemetry/esp32-node"
    for topic, bad in [
        ("dsn/telemetry/x", b"not json"),
        ("dsn/telemetry/x", json.dumps({"rssi": 50}).encode()),
        ("dsn/telemetry/x", json.dumps({"state": "PWNED"}).encode()),
        ("dsn/telemetry/x", b"{}" + b" " * 3000),
        ("dsn/telemetry/x/y", b"{}"),
        ("home/x", b"{}"),
    ]:
        assert consumer.handle(topic, bad) is False
    no_ingest = TelemetryConsumer(seen.append, None)
    assert no_ingest.handle("dsn/telemetry/esp32-node", payload)
    assert len(events) == 1  # broker log mode: telemetry only updates the registry


# --- provisioning --------------------------------------------------------------------


@pytest.fixture
def provision_mod() -> Any:
    pytest.importorskip("cryptography")
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import mqtt_provision

        yield mqtt_provision
    finally:
        sys.path.remove(str(ROOT / "scripts"))


def test_provisioning_pki_and_passwords(provision_mod: Any, tmp_path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    fw = tmp_path / "fw"
    creds = provision_mod.provision(
        tmp_path, ["mosquitto", "broker.lab"], ["192.168.50.2"], ["esp32-node"], firmware_dir=fw
    )
    ca = x509.load_pem_x509_certificate((tmp_path / "certs" / "ca.crt").read_bytes())
    server = x509.load_pem_x509_certificate((tmp_path / "certs" / "server.crt").read_bytes())
    ca_key = ca.public_key()
    assert isinstance(ca_key, ec.EllipticCurvePublicKey)
    server.verify_directly_issued_by(ca)
    sans = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["mosquitto", "broker.lab"]
    assert [str(i) for i in sans.get_values_for_type(x509.IPAddress)] == ["192.168.50.2"]
    users = creds["users"]
    assert set(users) == {"dsn-backend", "status-node", "esp32-node"}
    for line in (tmp_path / "passwd").read_text().splitlines():
        user, hashed = line.split(":", 1)
        _, scheme, iters, salt, digest = hashed.split("$")
        assert scheme == "7"
        recomputed = hashlib.pbkdf2_hmac(
            "sha512", users[user].encode(), base64.b64decode(salt), int(iters), dklen=64
        )
        assert base64.b64decode(digest) == recomputed
    device_file = (fw / "esp32-node.txt").read_text()
    assert users["esp32-node"] in device_file
    assert users["dsn-backend"] not in device_file  # no other client's secret
    assert "cmd_key" not in device_file  # only the status node gets the command key
    assert creds["command_key"] in (fw / "status-node.txt").read_text()
    # Idempotent: same CA and passwords on re-run; new devices are added.
    again = provision_mod.provision(
        tmp_path, ["mosquitto"], ["192.168.50.2"], ["esp32-node", "thermo-hall"]
    )
    assert again["users"]["esp32-node"] == users["esp32-node"]
    assert "thermo-hall" in again["users"]
    assert x509.load_pem_x509_certificate((tmp_path / "certs" / "ca.crt").read_bytes()) == ca
    rotated = provision_mod.provision(tmp_path, ["mosquitto"], [], [], rotate=True)
    assert rotated["users"]["esp32-node"] == users["esp32-node"]
    assert x509.load_pem_x509_certificate((tmp_path / "certs" / "ca.crt").read_bytes()) != ca
    with pytest.raises(SystemExit, match="invalid username"):
        provision_mod.provision(tmp_path, ["m"], [], ["bad name;"])
