from __future__ import annotations

import json
import random
import socket
import threading
from pathlib import Path

import pytest

from app.lab import attacks
from app.lab.client import LabConfig, SandboxError, own_identity
from app.lab.devices import PROFILES, Service, metric_message, start_services, telemetry_message
from app.lab.status_node import StatusNodeLogic, next_state
from app.mqtt.commands import sign
from app.mqtt.telemetry import Telemetry

KEY = b"status-node-command-key-0123456789abcdef"
NOW = 1_790_000_000


def command(cmd: str = "QUARANTINE", cid: str = "c-1", ts: int = NOW, **extra: object) -> bytes:
    payload: dict[str, object] = {
        "id": cid, "ts": ts, "cmd": cmd, "node_id": "dev-8b32829a42842662",
        "level": "critical", "ttl": 60,
    }  # fmt: skip
    payload["sig"] = sign(payload, KEY)
    payload.update(extra)
    return json.dumps(payload).encode()


# --- status node -------------------------------------------------------------------


def test_status_node_accepts_genuine_and_updates_state() -> None:
    node = StatusNodeLogic(KEY)
    assert node.handle(command(), NOW + 5) == ("c-1", "ok")
    assert node.state == "QUARANTINED"
    assert node.last_node == "dev-8b32829a42842662"
    assert node.handle(command("ALERT", cid="c-2"), NOW) == ("c-2", "ok")
    assert node.state == "QUARANTINED"  # ALERT never hides a quarantine
    assert node.handle(command("RECOVER", cid="c-3"), NOW) == ("c-3", "ok")
    assert str(node.state) == "NORMAL"


def test_status_node_shared_vector_matches_backend() -> None:
    # Same vector as test_iot_backend: the signer and this verifier must agree.
    raw = json.dumps({
        "id": "4a0f7c4e-1111-4222-8333-444455556666", "ts": 1790000000, "cmd": "QUARANTINE",
        "node_id": "dev-8b32829a42842662", "level": "critical", "ttl": 60,
        "sig": "80bf20325c28621746d8e521ea080dae4a88304630db3a9ba85f661bf60681e3",
    }).encode()  # fmt: skip
    assert StatusNodeLogic(KEY).handle(raw, 1790000000)[1] == "ok"


@pytest.mark.parametrize(
    ("raw", "now", "verdict"),
    [
        (b"not json", NOW, "bad_json"),
        (b"[1, 2]", NOW, "bad_json"),
        (b"\xff\xfe", NOW, "bad_json"),
        (b"{" + b" " * 2000 + b"}", NOW, "bad_json"),
        (json.dumps({"id": "x", "ts": "1", "ttl": 60, "sig": "s"}).encode(), NOW, "bad_field"),
        (json.dumps({"id": "", "ts": 1, "ttl": 60, "sig": "s"}).encode(), NOW, "bad_field"),
        (command("REBOOT"), NOW, "bad_cmd"),
        (command(cmd="RECOVER", sig="0" * 64), NOW, "bad_sig"),
        (command(node_id="dev|x"), NOW, "bad_sig"),  # tampered + unsafe field
        (command(), NOW + 61, "stale"),
        (command(), NOW - 61, "stale"),
    ],
)
def test_status_node_rejections(raw: bytes, now: int, verdict: str) -> None:
    node = StatusNodeLogic(KEY)
    assert node.handle(raw, now)[1] == verdict
    assert node.state == "NORMAL"


def test_status_node_replay_and_cache_not_poisoned() -> None:
    node = StatusNodeLogic(KEY)
    forged = command(sig="0" * 64)
    assert node.handle(forged, NOW)[1] == "bad_sig"
    assert node.handle(command(), NOW)[1] == "ok"  # the forged copy didn't burn the id
    assert node.handle(command(), NOW)[1] == "replay"


def test_status_node_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        StatusNodeLogic(b"short")


def test_next_state_unknown_command_keeps_state() -> None:
    assert next_state("BOGUS", "ALERT") == "ALERT"


# --- device profiles ----------------------------------------------------------------


def test_profiles_produce_valid_messages() -> None:
    rng = random.Random(1)
    for name, profile in PROFILES.items():
        for metric in profile.metrics:
            topic, body = metric_message("dev1", metric, rng)
            assert topic == f"home/dev1/{metric.topic}"
            assert isinstance(json.loads(body), dict), name
        topic, body = telemetry_message(
            "dev1", mac="24:0a:c4:00:00:01", ip="10.77.1.11", fw=profile.fw,
            uptime_s=5, state="NORMAL", seq=1, rng=rng,
        )  # fmt: skip
        assert topic == "dsn/telemetry/dev1"
        Telemetry.model_validate(json.loads(body))  # what the backend accepts


def test_payloads_are_reproducible() -> None:
    metric = PROFILES["thermostat"].metrics[0]
    a = [metric_message("t", metric, random.Random(3)) for _ in range(3)]
    b = [metric_message("t", metric, random.Random(3)) for _ in range(3)]
    assert a == b


def test_vulncam_banner_is_the_kev_goahead_version() -> None:
    banners = b"".join(s.banner for s in PROFILES["vulncam"].services)
    assert b"Server: GoAhead-Webs/3.6.4" in banners  # < 3.6.5: CVE-2017-17562 (KEV)
    assert b"GoAhead" not in b"".join(s.banner for s in PROFILES["camera"].services)


def test_banner_service_answers_any_request() -> None:
    servers = start_services([Service(0, b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n")], "127.0.0.1")
    try:
        port = servers[0].server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert b"Server: test" in s.recv(1024)
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


# --- config / sandbox guards ---------------------------------------------------------


def _creds(tmp_path: Path, **extra: str) -> Path:
    path = tmp_path / "client.json"
    path.write_text(json.dumps({"username": "plug-lab", "password": "pw", **extra}))
    return path


def test_lab_config_from_env(tmp_path: Path) -> None:
    cfg = LabConfig.from_env(
        {"DSN_LAB_CREDENTIALS": str(_creds(tmp_path, command_key="k")), "DSN_LAB_SANDBOX": "1"}
    )
    assert (cfg.username, cfg.password, cfg.command_key, cfg.sandbox) == (
        "plug-lab",
        "pw",
        "k",
        True,
    )
    assert (cfg.broker, cfg.port) == ("10.77.2.10", 8883)


@pytest.mark.parametrize(
    ("broker", "sandbox", "match"),
    [
        ("10.77.2.10", False, "DSN_LAB_SANDBOX"),
        ("8.8.8.8", True, "not a private lab address"),
        ("127.0.0.1", True, "not a private lab address"),
        ("bad host name !", True, "cannot resolve"),
    ],
)
def test_sandbox_guard_refuses(tmp_path: Path, broker: str, sandbox: bool, match: str) -> None:
    cfg = LabConfig.from_env(
        {
            "DSN_LAB_CREDENTIALS": str(_creds(tmp_path)),
            "DSN_LAB_BROKER": broker,
            "DSN_LAB_SANDBOX": "1" if sandbox else "0",
        }
    )
    with pytest.raises(SandboxError, match=match):
        cfg.require_sandbox()
    stop = threading.Event()
    with pytest.raises(SandboxError):
        attacks.connect_flood(cfg, 10, 0.1, stop)
    with pytest.raises(SandboxError):
        attacks.wildcard_subscribe(cfg, 1, stop)
    with pytest.raises(SandboxError):
        attacks.restricted_publish(cfg, 1, stop)
    with pytest.raises(SandboxError):
        attacks.bad_auth(cfg, 1, stop)


def test_sandbox_guard_accepts_private_broker(tmp_path: Path) -> None:
    cfg = LabConfig.from_env(
        {"DSN_LAB_CREDENTIALS": str(_creds(tmp_path)), "DSN_LAB_BROKER": "10.77.2.10",
         "DSN_LAB_SANDBOX": "1"}
    )  # fmt: skip
    cfg.require_sandbox()


def test_c2_beacon_requires_sandbox_and_ip_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = threading.Event()
    monkeypatch.delenv("DSN_LAB_SANDBOX", raising=False)
    with pytest.raises(SandboxError):
        attacks.c2_beacon("162.243.103.246:8080", 1, 0, stop)
    monkeypatch.setenv("DSN_LAB_SANDBOX", "1")
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6"):
        attacks.c2_beacon("evil.example:8080", 1, 0, stop)  # never resolves names


def test_c2_beacon_counts_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DSN_LAB_SANDBOX", "1")
    calls: list[tuple[str, int]] = []

    def refuse(addr: tuple[str, int], timeout: float) -> socket.socket:
        calls.append(addr)
        raise OSError("dropped")

    monkeypatch.setattr(socket, "create_connection", refuse)
    assert attacks.c2_beacon("162.243.103.246:8080", 3, 0, threading.Event()) == 3
    assert calls == [("162.243.103.246", 8080)] * 3


def test_flood_stops_when_the_device_is_cut_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: a quarantined device kept "flooding" (1,000 x 3 s timeouts ≈ 50 min).
    cfg = LabConfig.from_env(
        {"DSN_LAB_CREDENTIALS": str(_creds(tmp_path)), "DSN_LAB_BROKER": "10.77.2.10",
         "DSN_LAB_SANDBOX": "1"}
    )  # fmt: skip
    attempts: list[int] = []
    monkeypatch.setattr(attacks, "mqtt_client", lambda cfg, cid, password=None: object())

    def refused(client: object, cfg: object, timeout: float = 5.0) -> bool:
        attempts.append(1)
        return False

    monkeypatch.setattr(attacks, "_connected", refused)
    monkeypatch.setattr(attacks, "_close", lambda c: None)
    assert attacks.connect_flood(cfg, per_minute=1200, minutes=2, stop=threading.Event()) == 0
    assert len(attempts) == attacks.MAX_FAILURES_IN_A_ROW


def test_own_identity_picks_routed_ip() -> None:
    _mac, ip = own_identity("127.0.0.1", 9)
    assert ip == "127.0.0.1"
