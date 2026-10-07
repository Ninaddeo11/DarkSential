"""Traffic events: the unit the behavior pipeline consumes.

Produced by the pcap converter (``pcap.py``), the traffic simulator, and (from
Phase 5) the MQTT telemetry consumer. One event = one request/flow start/message,
not one packet.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.detect.observations import clean_label

MqttPacket = Literal[
    "CONNECT", "CONNACK", "PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE", "PINGREQ", "DISCONNECT", "OTHER"
]


class MqttInfo(BaseModel):
    packet: MqttPacket
    topic: str | None = Field(default=None, max_length=1024)
    client_id: str | None = None

    @field_validator("client_id")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return clean_label(v, 128)


class TrafficEvent(BaseModel):
    ts: datetime
    src_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str = Field(min_length=1, max_length=16, pattern=r"^[a-z0-9_-]+$")
    bytes: int = Field(default=0, ge=0)
    ok: bool | None = None  # outcome of auth/connection when known
    dns_query: str | None = Field(default=None, max_length=255)
    mqtt: MqttInfo | None = None
