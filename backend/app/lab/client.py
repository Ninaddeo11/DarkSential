"""Lab client plumbing: config from env, own identity, TLS MQTT client, run loops."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import random
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.lab.devices import PROFILES, metric_message, start_services, telemetry_message
from app.lab.status_node import StatusNodeLogic

log = logging.getLogger(__name__)

TELEMETRY_EVERY_S = 10.0
COMMAND_TOPIC = "dsn/cmd/{user}"
ACK_TOPIC = "dsn/ack/{user}"


class SandboxError(RuntimeError):
    """Raised when lab-only behavior is attempted outside the virtual lab."""


@dataclass(frozen=True)
class LabConfig:
    broker: str
    port: int
    ca_file: Path
    username: str
    password: str
    command_key: str | None
    sandbox: bool

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LabConfig:
        env = dict(os.environ if env is None else env)
        creds_path = Path(env.get("DSN_LAB_CREDENTIALS", "/run/lab/client.json"))
        creds = json.loads(creds_path.read_text(encoding="utf-8"))
        return cls(
            broker=env.get("DSN_LAB_BROKER", "10.77.2.10"),
            port=int(env.get("DSN_LAB_PORT", "8883")),
            ca_file=Path(env.get("DSN_LAB_CA", "/run/lab/ca.crt")),
            username=str(creds["username"]),
            password=str(creds["password"]),
            command_key=creds.get("command_key"),
            sandbox=env.get("DSN_LAB_SANDBOX") == "1",
        )

    def require_sandbox(self) -> None:
        """Lab clients only ever talk to a private broker inside the sandbox."""
        if not self.sandbox:
            raise SandboxError("refusing: DSN_LAB_SANDBOX=1 is set only inside lab containers")
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(self.broker))
        except (OSError, ValueError) as exc:
            raise SandboxError(f"cannot resolve lab broker {self.broker!r}") from exc
        if not addr.is_private or addr.is_loopback:
            raise SandboxError(f"lab broker {addr} is not a private lab address")


def own_identity(broker: str, port: int) -> tuple[str | None, str | None]:
    """(mac, ip) of the interface that routes to the broker (no packets sent)."""
    ip: str | None = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((broker, port))  # UDP connect only selects a route
            ip = s.getsockname()[0]
    except OSError:
        pass
    mac: str | None = None
    for iface in (
        sorted(Path("/sys/class/net").glob("*")) if Path("/sys/class/net").exists() else []
    ):
        if iface.name == "lo":
            continue
        try:
            mac = (iface / "address").read_text().strip() or None
            break
        except OSError:
            continue
    return mac, ip


def mqtt_client(cfg: LabConfig, client_id: str, password: str | None = None) -> Any:
    import paho.mqtt.client as mqtt
    from paho.mqtt.enums import CallbackAPIVersion

    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id)
    client.username_pw_set(cfg.username, cfg.password if password is None else password)
    client.tls_set(ca_certs=str(cfg.ca_file))  # verifies the broker cert + hostname/IP
    client.reconnect_delay_set(min_delay=1, max_delay=60)
    return client


def _connect_loop(client: Any, cfg: LabConfig) -> None:
    client.connect_async(cfg.broker, cfg.port, keepalive=30)
    client.loop_start()  # paho reconnects with backoff (1..60 s) on its own


def run_device(cfg: LabConfig, profile_name: str, seed: int, stop: threading.Event) -> None:
    cfg.require_sandbox()
    profile = PROFILES[profile_name]
    rng = random.Random(f"{seed}:{cfg.username}")  # noqa: S311 - simulated data
    mac, ip = own_identity(cfg.broker, cfg.port)
    start_services(profile.services)
    client = mqtt_client(cfg, f"{cfg.username}-{profile.kind}")
    _connect_loop(client, cfg)
    started = time.monotonic()
    due = {m.topic: started + rng.uniform(0, m.every_s) for m in profile.metrics}
    next_telemetry, seq = started, 0
    log.info("device up", extra={"user": cfg.username, "profile": profile_name, "ip": ip})
    try:
        while not stop.is_set():
            now = time.monotonic()
            for metric in profile.metrics:
                if now >= due[metric.topic]:
                    topic, body = metric_message(cfg.username, metric, rng)
                    client.publish(topic, body, qos=0)
                    due[metric.topic] = now + metric.every_s * rng.uniform(0.9, 1.1)
            if now >= next_telemetry:
                seq += 1
                topic, body = telemetry_message(
                    cfg.username, mac=mac, ip=ip, fw=profile.fw,
                    uptime_s=int(now - started), state="NORMAL", seq=seq, rng=rng,
                )  # fmt: skip
                client.publish(topic, body, qos=1)
                next_telemetry = now + TELEMETRY_EVERY_S
            stop.wait(0.2)
    finally:
        client.loop_stop()
        client.disconnect()


def run_status_node(cfg: LabConfig, seed: int, stop: threading.Event) -> None:
    cfg.require_sandbox()
    if not cfg.command_key:
        raise SystemExit("status node needs command_key in its credentials file")
    logic = StatusNodeLogic(cfg.command_key.encode("utf-8"))
    rng = random.Random(f"{seed}:{cfg.username}")  # noqa: S311 - simulated data
    mac, ip = own_identity(cfg.broker, cfg.port)
    client = mqtt_client(cfg, f"{cfg.username}-node")
    cmd_topic = COMMAND_TOPIC.format(user=cfg.username)
    ack_topic = ACK_TOPIC.format(user=cfg.username)
    publish_now = threading.Event()

    def on_connect(c: Any, userdata: Any, flags: Any, reason: Any, props: Any) -> None:
        if not reason.is_failure:
            c.subscribe(cmd_topic, qos=1)

    def on_message(c: Any, userdata: Any, msg: Any) -> None:
        if msg.topic != cmd_topic:
            return
        cid, verdict = logic.handle(msg.payload, int(time.time()))
        log.info("command", extra={"verdict": verdict, "state": logic.state})
        c.publish(ack_topic, json.dumps({"id": cid, "status": verdict}), qos=1)
        publish_now.set()  # report the new state right away

    client.on_connect = on_connect
    client.on_message = on_message
    _connect_loop(client, cfg)
    started, seq = time.monotonic(), 0
    try:
        while not stop.is_set():
            seq += 1
            topic, body = telemetry_message(
                cfg.username, mac=mac, ip=ip, fw="status-1.0.0",
                uptime_s=int(time.monotonic() - started), state=logic.state, seq=seq, rng=rng,
            )  # fmt: skip
            client.publish(topic, body, qos=1)
            publish_now.wait(TELEMETRY_EVERY_S)
            publish_now.clear()
    finally:
        client.loop_stop()
        client.disconnect()
