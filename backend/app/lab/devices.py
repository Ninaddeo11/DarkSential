"""Virtual IoT device profiles: what each device publishes and which services it exposes.

Payloads are generated from a seeded RNG, so a lab run is reproducible. Every
device also sends DSN telemetry (``dsn/telemetry/<user>``) like real firmware.
Service banners are what nmap ``-sV`` fingerprints: ``vulncam`` deliberately
answers as GoAhead 3.6.4 (CVE-2017-17562, in CISA KEV) so the risk engine's
vulnerable-service factor can be exercised without any real vulnerable code.
"""

from __future__ import annotations

import contextlib
import json
import logging
import random
import socketserver
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

Payload = Callable[[random.Random], dict[str, object]]


@dataclass(frozen=True)
class Metric:
    topic: str  # suffix under home/<user>/
    every_s: float
    payload: Payload


@dataclass(frozen=True)
class Service:
    port: int
    banner: bytes  # full response sent to any request (no request parsing)


@dataclass(frozen=True)
class Profile:
    kind: str
    fw: str
    metrics: list[Metric] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)


def _http(server: str) -> bytes:
    body = b"<html><body>device</body></html>"
    head = (
        "HTTP/1.1 200 OK\r\n"
        f"Server: {server}\r\n"
        "Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return head.encode("ascii") + body


_RTSP = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, PLAY, TEARDOWN\r\n\r\n"


def _motion(r: random.Random) -> dict[str, object]:
    return {"motion": r.random() < 0.15, "lux": round(r.uniform(5, 900), 1)}


def _snapshot(r: random.Random) -> dict[str, object]:
    return {"frame": r.randrange(1 << 30), "bytes": r.randrange(40_000, 90_000)}


def _temperature(r: random.Random) -> dict[str, object]:
    return {"temp_c": round(r.gauss(21.5, 0.6), 2), "setpoint_c": 21.0, "heating": r.random() < 0.4}


def _power(r: random.Random) -> dict[str, object]:
    return {"watts": round(max(0.0, r.gauss(38, 6)), 1), "on": True}


def _air(r: random.Random) -> dict[str, object]:
    return {"humidity": round(r.uniform(35, 55), 1), "co2_ppm": r.randrange(420, 900)}


PROFILES: dict[str, Profile] = {
    "camera": Profile(
        kind="camera",
        fw="cam-5.7.3",
        metrics=[Metric("motion", 20, _motion), Metric("snapshot", 60, _snapshot)],
        services=[Service(80, _http("lighttpd/1.4.76")), Service(554, _RTSP)],
    ),
    "vulncam": Profile(
        kind="camera",
        fw="cam-2.1.0",
        metrics=[Metric("motion", 20, _motion), Metric("snapshot", 60, _snapshot)],
        services=[Service(80, _http("GoAhead-Webs/3.6.4")), Service(554, _RTSP)],
    ),
    "thermostat": Profile(
        kind="thermostat", fw="th-1.4.2", metrics=[Metric("temp", 15, _temperature)]
    ),
    "plug": Profile(kind="smart-plug", fw="plug-3.0.1", metrics=[Metric("power", 10, _power)]),
    "sensor": Profile(kind="air-sensor", fw="air-0.9.8", metrics=[Metric("air", 30, _air)]),
}


def metric_message(user: str, metric: Metric, rng: random.Random) -> tuple[str, str]:
    return f"home/{user}/{metric.topic}", json.dumps(metric.payload(rng), separators=(",", ":"))


def telemetry_message(
    user: str,
    *,
    mac: str | None,
    ip: str | None,
    fw: str,
    uptime_s: int,
    state: str,
    seq: int,
    rng: random.Random,
) -> tuple[str, str]:
    body = {
        "v": 1,
        "mac": mac,
        "ip": ip,
        "fw": fw,
        "uptime_s": uptime_s,
        "rssi": rng.randrange(-72, -45),
        "heap": rng.randrange(150_000, 210_000),
        "state": state,
        "seq": seq,
    }
    return f"dsn/telemetry/{user}", json.dumps(body, separators=(",", ":"))


class _BannerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(3)
        with contextlib.suppress(OSError):
            self.request.recv(2048)  # read (and ignore) at most one request chunk
        try:
            self.request.sendall(self.server.banner)  # type: ignore[attr-defined]
        except OSError:
            log.debug("banner client went away")


class _BannerServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], banner: bytes) -> None:
        self.banner = banner
        super().__init__(address, _BannerHandler)


def start_services(services: list[Service], host: str = "0.0.0.0") -> list[_BannerServer]:  # noqa: S104 - lab device listens on its lab interface
    servers = []
    for svc in services:
        server = _BannerServer((host, svc.port), svc.banner)
        threading.Thread(target=server.serve_forever, daemon=True, name=f"svc-{svc.port}").start()
        servers.append(server)
    return servers
