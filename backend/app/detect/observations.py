"""What discovery sources report about a device.

Observations carry the raw MAC only in memory; the registry converts it to an
HMAC before anything is stored or emitted. Free-text fields (hostnames, BLE
names, banners) come from devices, which are untrusted (threat model D3), and
are sanitized and length-capped on construction.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.intel.sanitize import sanitize_text

ObservationSource = Literal["nmap", "arp", "dhcp", "mdns", "ble", "traffic", "manual"]


def clean_label(value: str | None, limit: int = 128) -> str | None:
    if value is None:
        return None
    text = sanitize_text(value, max_chars=limit).text.replace("\n", " ").strip()
    return text or None


class Service(BaseModel):
    port: int = Field(ge=0, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: list[str] = Field(default_factory=list)  # as reported by nmap (2.2 URI or 2.3)

    @field_validator("name", "product", "version")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return clean_label(v, 96)

    @property
    def key(self) -> str:
        return f"{self.port}/{self.proto}"


class Observation(BaseModel):
    source: ObservationSource
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mac: str | None = None
    ip: str | None = None
    # Identifier for devices without a usable MAC (e.g. macOS BLE UUIDs).
    alt_id: str | None = Field(default=None, max_length=128)
    hostname: str | None = None
    services: list[Service] = Field(default_factory=list)
    # Host-level CPEs (e.g. nmap OS detection: firmware/OS CPE URIs).
    host_cpes: list[str] = Field(default_factory=list, max_length=16)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def _clean_host(cls, v: str | None) -> str | None:
        # Hostnames never legitimately contain markup characters; drop them as
        # defense in depth (the UI escapes as well).
        cleaned = clean_label(v, 255)
        if cleaned is None:
            return None
        return re.sub(r"[<>\"'`]", "", cleaned) or None

    @field_validator("attributes")
    @classmethod
    def _clean_attrs(cls, attrs: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in list(attrs.items())[:32]:
            k = clean_label(str(key), 64) or "_"
            if isinstance(value, str):
                out[k] = clean_label(value, 256)
            elif isinstance(value, list):
                out[k] = [clean_label(str(v), 128) if isinstance(v, str) else v for v in value[:32]]
            elif isinstance(value, int | float | bool) or value is None:
                out[k] = value
            else:
                out[k] = clean_label(str(value), 256)
        return out
