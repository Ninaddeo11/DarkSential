"""Deterministic (seeded) IoT traffic simulator.

Device profiles emit realistic periodic traffic with jitter. Attack injectors
add labelled malicious events. Same seed means byte-identical output. Used for:
Isolation Forest training (normal windows), tests, demos, and the Phase 7
evaluation scenarios.

All addresses are in the lab range; MACs use real IoT vendor OUIs so vendor
lookup is exercised.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from app.behavior.events import MqttInfo, TrafficEvent

BROKER = "192.168.50.2"
NVR = "192.168.50.10"
DNS = "192.168.50.1"
CLOUD = "203.0.113.50"

Profile = Literal["camera", "thermostat", "smart_plug", "esp32_sensor"]


@dataclass(frozen=True)
class SimDevice:
    name: str
    mac: str
    ip: str
    profile: Profile


DEFAULT_FLEET: tuple[SimDevice, ...] = (
    SimDevice("cam-front", "44:19:b6:10:00:01", "192.168.50.21", "camera"),  # Hikvision OUI
    SimDevice("thermo-hall", "18:b4:30:20:00:02", "192.168.50.22", "thermostat"),  # Nest OUI
    SimDevice("plug-desk", "50:c7:bf:30:00:03", "192.168.50.23", "smart_plug"),  # TP-Link OUI
    SimDevice("esp32-node", "24:0a:c4:40:00:04", "192.168.50.24", "esp32_sensor"),  # Espressif
)


@dataclass
class Labelled:
    event: TrafficEvent
    label: str = "normal"  # normal | <attack name>
    device: str = ""


@dataclass
class TrafficSimulator:
    seed: int = 0
    fleet: tuple[SimDevice, ...] = DEFAULT_FLEET
    _rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    # --- helpers ---------------------------------------------------------------------

    def _ev(self, dev: SimDevice, ts: datetime, **kw: object) -> TrafficEvent:
        return TrafficEvent(ts=ts, src_mac=dev.mac, src_ip=dev.ip, **kw)  # type: ignore[arg-type]

    def _jitter(self, base: float, frac: float = 0.1) -> float:
        return max(0.05, base * (1 + self._rng.uniform(-frac, frac)))

    # --- normal profiles -------------------------------------------------------------

    def normal(self, start: datetime, minutes: int) -> list[Labelled]:
        out: list[Labelled] = []
        end = start + timedelta(minutes=minutes)
        for dev in self.fleet:
            out += [Labelled(e, "normal", dev.name) for e in self._profile(dev, start, end)]
        out.sort(key=lambda le: (le.event.ts, le.device))
        return out

    def _profile(self, dev: SimDevice, start: datetime, end: datetime) -> Iterator[TrafficEvent]:
        rng = self._rng
        if dev.profile in {"thermostat", "smart_plug", "esp32_sensor"}:
            yield self._ev(
                dev,
                start,
                dst_ip=BROKER,
                dst_port=8883,
                proto="mqtt",
                bytes=120,
                ok=True,
                mqtt=MqttInfo(packet="CONNECT", client_id=dev.name),
            )
        period = {"camera": 2.0, "thermostat": 30.0, "smart_plug": 60.0, "esp32_sensor": 10.0}
        t = start + timedelta(seconds=rng.uniform(0, period[dev.profile]))
        last_dns = last_ping = last_cloud = start
        # Benign MQTT reconnects (keep-alive timeouts, Wi-Fi roaming) every 20-40 min;
        # ~5% fail auth once (e.g. a token refresh race) and are retried. Real devices
        # do this, and it gives the Isolation Forest variance on connect/failure
        # features, which it cannot split on if they are constant in training.
        mqtt_device = dev.profile in {"thermostat", "smart_plug", "esp32_sensor"}
        next_reconnect = start + timedelta(minutes=rng.uniform(20, 40))
        while t < end:
            if mqtt_device and t >= next_reconnect:
                next_reconnect = t + timedelta(minutes=rng.uniform(20, 40))
                if rng.random() < 0.05:
                    yield self._ev(
                        dev,
                        t,
                        dst_ip=BROKER,
                        dst_port=8883,
                        proto="mqtt",
                        bytes=120,
                        ok=False,
                        mqtt=MqttInfo(packet="CONNECT", client_id=dev.name),
                    )
                yield self._ev(
                    dev,
                    t,
                    dst_ip=BROKER,
                    dst_port=8883,
                    proto="mqtt",
                    bytes=120,
                    ok=True,
                    mqtt=MqttInfo(packet="CONNECT", client_id=dev.name),
                )
            if dev.profile == "camera":
                yield self._ev(
                    dev, t, dst_ip=NVR, dst_port=554, proto="rtsp", bytes=int(rng.gauss(1200, 120))
                )
            else:
                topic = {
                    "thermostat": f"home/{dev.name}/temp",
                    "smart_plug": f"home/{dev.name}/power",
                    "esp32_sensor": f"dsn/telemetry/{dev.name}",
                }[dev.profile]
                yield self._ev(
                    dev,
                    t,
                    dst_ip=BROKER,
                    dst_port=8883,
                    proto="mqtt",
                    bytes=int(rng.gauss(90, 8)),
                    mqtt=MqttInfo(packet="PUBLISH", topic=topic),
                )
                if (t - last_ping).total_seconds() >= 60:
                    last_ping = t
                    yield self._ev(
                        dev,
                        t,
                        dst_ip=BROKER,
                        dst_port=8883,
                        proto="mqtt",
                        bytes=2,
                        mqtt=MqttInfo(packet="PINGREQ"),
                    )
            if (t - last_dns).total_seconds() >= 300:
                last_dns = t
                yield self._ev(
                    dev, t, dst_ip=DNS, dst_port=53, proto="dns", bytes=60, dns_query="pool.ntp.org"
                )
                yield self._ev(dev, t, dst_ip="198.51.100.123", dst_port=123, proto="ntp", bytes=76)
            if dev.profile == "smart_plug" and (t - last_cloud).total_seconds() >= 300:
                last_cloud = t
                yield self._ev(
                    dev,
                    t,
                    dst_ip=CLOUD,
                    dst_port=443,
                    proto="https",
                    bytes=int(rng.gauss(900, 100)),
                )
            t += timedelta(seconds=self._jitter(period[dev.profile]))

    # --- attacks ---------------------------------------------------------------------

    def device(self, name: str) -> SimDevice:
        return next(d for d in self.fleet if d.name == name)

    def mqtt_flood(
        self, dev: SimDevice, start: datetime, minutes: int, per_minute: int = 500
    ) -> list[Labelled]:
        out = []
        for i in range(minutes * per_minute):
            ts = start + timedelta(seconds=i * 60 / per_minute + self._rng.uniform(0, 0.05))
            out.append(
                Labelled(
                    self._ev(
                        dev,
                        ts,
                        dst_ip=BROKER,
                        dst_port=8883,
                        proto="mqtt",
                        bytes=110,
                        ok=self._rng.random() > 0.3,
                        mqtt=MqttInfo(packet="CONNECT", client_id=f"x{i}"),
                    ),
                    "mqtt_flood",
                    dev.name,
                )
            )
        return out

    def port_scan(self, dev: SimDevice, start: datetime, ports: int = 200) -> list[Labelled]:
        targets = [f"192.168.50.{h}" for h in range(1, 11)]
        out = []
        for i in range(ports):
            ts = start + timedelta(seconds=i * 0.2)
            out.append(
                Labelled(
                    self._ev(
                        dev,
                        ts,
                        dst_ip=targets[i % len(targets)],
                        dst_port=1 + i * 7 % 1024,
                        proto="tcp",
                        bytes=60,
                        # Connection attempts only: no authentication happened, so
                        # `ok` stays None (a refused SYN is not a failed login).
                    ),
                    "port_scan",
                    dev.name,
                )
            )
        return out

    def brute_force(self, dev: SimDevice, start: datetime, attempts: int = 60) -> list[Labelled]:
        return [
            Labelled(
                self._ev(
                    dev,
                    start + timedelta(seconds=i),
                    dst_ip="192.168.50.30",
                    dst_port=23,
                    proto="telnet",
                    bytes=80,
                    ok=False,
                ),
                "brute_force",
                dev.name,
            )
            for i in range(attempts)
        ]

    def wildcard_subscribe(self, dev: SimDevice, start: datetime) -> list[Labelled]:
        return [
            Labelled(
                self._ev(
                    dev,
                    start,
                    dst_ip=BROKER,
                    dst_port=8883,
                    proto="mqtt",
                    bytes=20,
                    mqtt=MqttInfo(packet="SUBSCRIBE", topic="#"),
                ),
                "wildcard_subscribe",
                dev.name,
            )
        ]

    def restricted_publish(self, dev: SimDevice, start: datetime) -> list[Labelled]:
        return [
            Labelled(
                self._ev(
                    dev,
                    start,
                    dst_ip=BROKER,
                    dst_port=8883,
                    proto="mqtt",
                    bytes=64,
                    mqtt=MqttInfo(packet="PUBLISH", topic="dsn/cmd/quarantine/all"),
                ),
                "restricted_publish",
                dev.name,
            )
        ]


def merge(*streams: list[Labelled]) -> list[Labelled]:
    out = [le for s in streams for le in s]
    out.sort(key=lambda le: (le.event.ts, le.device, le.label))
    return out
