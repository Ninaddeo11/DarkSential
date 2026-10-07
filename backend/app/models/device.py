"""Device registry, detections and behavior baselines.

Raw MAC addresses are never stored: ``mac_hmac`` = HMAC-SHA256(key, MAC). The
OUI (first 24 bits, the vendor block) is kept for vendor display; on its own it
does not identify a device.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, UTCDateTime


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    # HMAC of the MAC (or of "ip:<addr>" for provisional IP-only identities).
    identity_hmac: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    identity_kind: Mapped[str] = mapped_column(String(16))  # mac | ble | ip
    oui: Mapped[str | None] = mapped_column(String(8), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    randomized_mac: Mapped[bool] = mapped_column(default=False)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    trust: Mapped[str] = mapped_column(String(16), default="unknown")  # unknown|known|approved
    services: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    cpes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # rule | anomaly
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    window_start: Mapped[datetime] = mapped_column(UTCDateTime())
    window_end: Mapped[datetime] = mapped_column(UTCDateTime())
    summary: Mapped[str] = mapped_column(Text, default="")


class DeviceBaseline(Base):
    __tablename__ = "device_baselines"

    node_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())
