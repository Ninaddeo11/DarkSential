"""Device telemetry over MQTT -> device registry (+ traffic events if no broker log).

Topic ``dsn/telemetry/<username>``. The broker ACL (``pattern write
dsn/telemetry/%u``) guarantees the publisher *is* <username>, so the topic is
authenticated identity; the payload is still device-controlled and validated.

Payload (virtual lab devices, ``app.lab``), JSON, <= 2 KiB::

    {"v": 1, "mac": "24:0a:c4:..", "ip": "192.168.50.24", "fw": "0.1.0",
     "uptime_s": 123, "rssi": -61, "heap": 182000, "state": "NORMAL", "seq": 42}
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.behavior.events import MqttInfo, TrafficEvent
from app.detect.observations import Observation

log = logging.getLogger(__name__)

TELEMETRY_TOPIC = "dsn/telemetry/+"
MAX_PAYLOAD = 2048


class Telemetry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    v: Literal[1] = 1
    mac: str | None = Field(default=None, max_length=17)
    ip: str | None = Field(default=None, max_length=45)
    fw: str | None = Field(default=None, max_length=32, pattern=r"^[A-Za-z0-9._-]*$")
    uptime_s: int | None = Field(default=None, ge=0)
    rssi: int | None = Field(default=None, ge=-127, le=0)
    heap: int | None = Field(default=None, ge=0)
    state: Literal["BOOT", "PROVISION", "NORMAL", "ALERT", "QUARANTINED", "OFFLINE"] | None = None
    seq: int | None = Field(default=None, ge=0)


class TelemetryConsumer:
    def __init__(
        self,
        observe: Callable[[Observation], object],
        ingest: Callable[[list[TrafficEvent]], object] | None,
        broker_ip: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.observe = observe
        self.ingest = ingest  # None when the broker log already provides traffic events
        self.broker_ip = broker_ip
        self.clock = clock

    def handle(self, topic: str, payload: bytes) -> bool:
        parts = topic.split("/")
        if len(parts) != 3 or parts[:2] != ["dsn", "telemetry"] or len(payload) > MAX_PAYLOAD:
            return False
        username = parts[2][:64]
        try:
            data = Telemetry.model_validate(json.loads(payload.decode("utf-8")))
            obs = Observation(
                source="telemetry",
                ts=self.clock(),
                mac=data.mac,
                ip=data.ip,
                hostname=username,
                attributes={
                    k: v
                    for k, v in data.model_dump(exclude={"v", "mac", "ip"}).items()
                    if v is not None
                }
                | {"mqtt_user": username},
            )
        except (ValueError, ValidationError, UnicodeDecodeError):
            log.warning("invalid telemetry", extra={"mqtt_user": username})
            return False
        self.observe(obs)
        if self.ingest is not None:
            self.ingest(
                [
                    TrafficEvent(
                        ts=obs.ts,
                        src_mac=data.mac,
                        src_ip=data.ip,
                        dst_ip=self.broker_ip,
                        dst_port=8883,
                        proto="mqtt",
                        bytes=len(payload),
                        mqtt=MqttInfo(packet="PUBLISH", topic=topic),
                    )
                ]
            )
        return True
