"""Scripted misbehavior for detection scenarios, run from inside a lab device.

These generate the *signals* DSN must detect. They are not exploits: they only
connect to the lab's own broker with the device's own (or a wrong) password, and
the "C2 beacon" only opens TCP connections that the lab gateway drops (the lab
networks are internal and the gateway forwards nothing outside the lab). Every
function refuses to run unless ``DSN_LAB_SANDBOX=1`` and the broker is private.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from typing import Any

from app.lab.client import LabConfig, SandboxError, mqtt_client

log = logging.getLogger(__name__)

MAX_FLOOD_PER_MINUTE = 1200
MAX_MINUTES = 10
MAX_FAILURES_IN_A_ROW = 10  # a flood from a cut-off device stops instead of hanging


def _connected(client: Any, cfg: LabConfig, timeout: float = 5.0) -> bool:
    done = threading.Event()
    ok: list[bool] = []

    def on_connect(c: Any, userdata: Any, flags: Any, reason: Any, props: Any) -> None:
        ok.append(not reason.is_failure)
        done.set()

    client.on_connect = on_connect
    try:
        client.connect(cfg.broker, cfg.port, keepalive=30)
    except OSError:
        return False
    client.loop_start()
    done.wait(timeout)
    return bool(ok and ok[0])


def _close(client: Any) -> None:
    try:
        client.disconnect()
    finally:
        client.loop_stop()


def connect_flood(cfg: LabConfig, per_minute: int, minutes: float, stop: threading.Event) -> int:
    """Rapid CONNECT/DISCONNECT cycles (T1498/T1499 signal). Returns successful connects."""
    cfg.require_sandbox()
    per_minute = min(max(per_minute, 1), MAX_FLOOD_PER_MINUTE)
    total = int(per_minute * min(minutes, MAX_MINUTES))
    gap = 60.0 / per_minute
    connects = 0
    failures_in_a_row = 0
    start = time.monotonic()
    deadline = start + min(minutes, MAX_MINUTES) * 60 + 30
    for i in range(total):
        if stop.is_set() or time.monotonic() > deadline:
            break
        client = mqtt_client(cfg, f"{cfg.username}-f{i}")
        if _connected(client, cfg, timeout=3.0):
            connects += 1
            failures_in_a_row = 0
        else:
            failures_in_a_row += 1
        _close(client)
        if failures_in_a_row >= MAX_FAILURES_IN_A_ROW:
            # The device has been cut off (e.g. quarantined): stop instead of retrying.
            log.info("flood stopped: broker unreachable", extra={"attempt": i + 1})
            break
        stop.wait(max(0.0, start + (i + 1) * gap - time.monotonic()))
    log.info("flood done", extra={"attempts": total, "connected": connects})
    return connects


def wildcard_subscribe(cfg: LabConfig, seconds: float, stop: threading.Event) -> bool:
    """Subscribe to everything and to the command topics (T1040 signal)."""
    cfg.require_sandbox()
    client = mqtt_client(cfg, f"{cfg.username}-sniff")
    if not _connected(client, cfg):
        return False
    for topic in ("#", "dsn/cmd/#", "$SYS/#"):
        client.subscribe(topic, qos=0)
    stop.wait(min(seconds, MAX_MINUTES * 60))
    _close(client)
    return True


def restricted_publish(cfg: LabConfig, count: int, stop: threading.Event) -> bool:
    """Publish to topics the ACL forbids: the command topic, another device's telemetry."""
    cfg.require_sandbox()
    client = mqtt_client(cfg, f"{cfg.username}-inject")
    if not _connected(client, cfg):
        return False
    for i in range(min(count, 100)):
        if stop.is_set():
            break
        client.publish("dsn/cmd/status-node", '{"cmd":"RECOVER"}', qos=1)
        client.publish("dsn/telemetry/cam-front", '{"v":1,"state":"NORMAL"}', qos=1)
        stop.wait(0.5 if i else 0.1)
    stop.wait(1.0)
    _close(client)
    return True


def bad_auth(cfg: LabConfig, attempts: int, stop: threading.Event) -> int:
    """Logins with a wrong password (T1110 signal). Returns refused attempts."""
    cfg.require_sandbox()
    refused = 0
    for i in range(min(attempts, 200)):
        if stop.is_set():
            break
        client = mqtt_client(cfg, f"{cfg.username}-guess{i}", password=f"wrong-{i}")
        if not _connected(client, cfg, timeout=3.0):
            refused += 1
        _close(client)
        stop.wait(1.0)
    return refused


def c2_beacon(target: str, count: int, interval: float, stop: threading.Event) -> int:
    """TCP connection attempts to a known-C2 address (dropped by the lab gateway)."""
    import os

    if os.environ.get("DSN_LAB_SANDBOX") != "1":
        raise SandboxError("refusing: c2 beacon only runs inside the virtual lab")
    host, _, port_s = target.rpartition(":")
    ipaddress.ip_address(host)  # an IP literal only, never a name to resolve
    port = int(port_s)
    attempts = 0
    for _ in range(min(count, 100)):
        if stop.is_set():
            break
        attempts += 1
        try:
            with socket.create_connection((host, port), timeout=2):
                log.warning("c2 target answered: the lab gateway is not filtering egress")
        except OSError:
            pass  # expected: dropped at the gateway
        stop.wait(interval)
    return attempts
