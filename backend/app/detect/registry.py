"""Device registry: stable identities, profiles, trust.

Identity
--------
* MAC seen        -> identity = HMAC(key, MAC), kind "mac" (or "ble").
* Only an IP seen -> attach to the device currently holding that IP; otherwise a
  *provisional* identity HMAC(key, "ip:<addr>"), kind "ip". When a later
  observation pairs that IP with a MAC, the provisional device is upgraded in
  place: same node_id, new identity.
* node_id = "dev-" + first 16 hex chars of the identity HMAC. It is stable,
  safe to show in the UI, and reveals nothing about the MAC.

Trust
-----
approved (allowlist or manual approval)  >  known (present >= known_after_hours)  >  unknown.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.events import EventBus
from app.core.identifiers import DeviceIdHasher, normalize_mac, oui
from app.detect import oui as oui_db
from app.detect.fingerprint import guess_cpes
from app.detect.observations import Observation, Service
from app.models.device import Device

log = logging.getLogger(__name__)

Trust = Literal["unknown", "known", "approved"]


class ApprovedEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mac: str | None = None
    hmac: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    name: str | None = None

    @model_validator(mode="after")
    def _one_of(self) -> ApprovedEntry:
        if (self.mac is None) == (self.hmac is None):
            raise ValueError("approved entry needs exactly one of mac / hmac")
        if self.mac is not None:
            normalize_mac(self.mac)  # validates
        return self


class DevicesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: list[ApprovedEntry] = Field(default_factory=list)
    known_after_hours: float = Field(default=24, gt=0)
    offline_after_minutes: float = Field(default=30, gt=0)


def load_devices_config(path: Path) -> DevicesConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return DevicesConfig.model_validate(raw)


class DeviceView(BaseModel):
    node_id: str
    identity_hmac: str
    identity_kind: str
    trust: Trust
    vendor: str | None
    oui: str | None
    randomized_mac: bool
    ip: str | None
    hostname: str | None
    services: list[dict[str, Any]]
    cpes: list[dict[str, Any]]
    sources: list[str]
    attributes: dict[str, Any]
    first_seen: datetime
    last_seen: datetime

    @classmethod
    def of(cls, d: Device) -> DeviceView:
        return cls(
            node_id=d.node_id,
            identity_hmac=d.identity_hmac,
            identity_kind=d.identity_kind,
            trust=d.trust,  # type: ignore[arg-type]
            vendor=d.vendor,
            oui=d.oui,
            randomized_mac=d.randomized_mac,
            ip=d.ip,
            hostname=d.hostname,
            services=list(d.services or []),
            cpes=list(d.cpes or []),
            sources=list(d.sources or []),
            attributes=dict(d.attributes or {}),
            first_seen=d.first_seen,
            last_seen=d.last_seen,
        )


def node_id_for(identity_hmac: str) -> str:
    return f"dev-{identity_hmac[:16]}"


def _valid_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip).compressed
    except ValueError:
        return None


class DeviceRegistry:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        hasher: DeviceIdHasher,
        config: DevicesConfig,
        bus: EventBus,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._sessions = sessions
        self._hasher = hasher
        self._config = config
        self._bus = bus
        self._clock = clock
        self._lock = threading.Lock()
        self._approved = {
            e.hmac if e.hmac else hasher.device_id(e.mac or "") for e in config.approved
        }

    # --- identity ------------------------------------------------------------------

    def identity_for(self, obs: Observation) -> tuple[str, str] | None:
        if obs.mac:
            return self._hasher.device_id(obs.mac), "ble" if obs.source == "ble" else "mac"
        if obs.alt_id:
            return self._hasher.keyed("alt", obs.alt_id), "ble" if obs.source == "ble" else "alt"
        ip = _valid_ip(obs.ip)
        if ip:
            return self._hasher.keyed("ip", ip), "ip"
        return None

    # --- writes --------------------------------------------------------------------

    def observe(self, obs: Observation) -> DeviceView | None:
        identity = self.identity_for(obs)
        if identity is None:
            log.debug("observation without mac/ip ignored", extra={"source": obs.source})
            return None
        identity_hmac, kind = identity
        ip = _valid_ip(obs.ip)
        now = obs.ts
        events: list[tuple[str, dict[str, Any]]] = []
        with self._lock, self._sessions.begin() as session:
            device = self._find(session, identity_hmac, kind, ip)
            created = device is None
            if device is None:
                device = Device(
                    node_id=node_id_for(identity_hmac),
                    identity_hmac=identity_hmac,
                    identity_kind=kind,
                    first_seen=now,
                    last_seen=now,
                    trust="unknown",
                    services=[],
                    cpes=[],
                    sources=[],
                    attributes={},
                    randomized_mac=False,
                )
                session.add(device)
            elif device.identity_kind == "ip" and kind != "ip":
                # Upgrade the provisional IP identity now that a MAC is known.
                device.identity_hmac, device.identity_kind = identity_hmac, kind
            returning = not created and now - device.last_seen > timedelta(
                minutes=self._config.offline_after_minutes
            )
            if obs.mac:
                device.oui = oui(obs.mac)
                device.randomized_mac = oui_db.is_locally_administered(obs.mac)
                device.vendor = oui_db.vendor_for(obs.mac) or device.vendor
            if ip and ip != device.ip:
                self._release_ip(session, ip, device.node_id)
                device.ip = ip
            if obs.hostname:
                device.hostname = obs.hostname
            device.last_seen = max(device.last_seen, now)
            device.sources = sorted({*(device.sources or []), obs.source})
            device.attributes = {**(device.attributes or {}), **obs.attributes}
            before = (list(device.services or []), list(device.cpes or []))
            host_cpes = sorted({*device.attributes.get("host_cpes", []), *obs.host_cpes})
            if obs.host_cpes:
                device.attributes = {**device.attributes, "host_cpes": host_cpes}
            if obs.services or obs.host_cpes:
                merged = {s["port_proto"]: s for s in device.services or []}
                for svc in obs.services:
                    merged[svc.key] = {"port_proto": svc.key, **svc.model_dump()}
                device.services = sorted(merged.values(), key=lambda s: s["port"])
                device.cpes = guess_cpes(
                    [Service(**_svc(s)) for s in device.services or []], host_cpes
                )
            device.trust = self._trust_for(device, now)
            session.flush()
            view = DeviceView.of(device)
            if created or returning:
                events.append(
                    (
                        "DEVICE_CONNECTED",
                        {
                            "returning": returning,
                            "trust": view.trust,
                            "vendor": view.vendor,
                            "ip": view.ip,
                            "source": obs.source,
                        },
                    )
                )
            if (view.services, view.cpes) != before and (view.services or view.cpes):
                events.append(
                    (
                        "DEVICE_PROFILED",
                        {
                            "vendor": view.vendor,
                            "hostname": view.hostname,
                            "services": [s["port_proto"] for s in view.services],
                            "cpes": view.cpes,
                        },
                    )
                )
        for type_, payload in events:
            self._bus.emit(type_, view.node_id, **payload)  # type: ignore[arg-type]
        return view

    def _find(
        self, session: Session, identity_hmac: str, kind: str, ip: str | None
    ) -> Device | None:
        device = session.scalars(
            select(Device).where(Device.identity_hmac == identity_hmac)
        ).first()
        if device is not None or ip is None:
            return device
        holder = session.scalars(
            select(Device).where(Device.ip == ip).order_by(Device.last_seen.desc())
        ).first()
        if holder is None:
            return None
        if kind == "ip":
            return holder  # IP-only sighting of a device we already know
        if holder.identity_kind == "ip":
            return holder  # provisional identity -> upgrade
        return None  # a different MAC now holds this IP (DHCP reassignment)

    def _release_ip(self, session: Session, ip: str, keep: str) -> None:
        for other in session.scalars(select(Device).where(Device.ip == ip, Device.node_id != keep)):
            other.ip = None

    def _trust_for(self, device: Device, now: datetime) -> Trust:
        if device.trust == "approved" or device.identity_hmac in self._approved:
            return "approved"
        if now - device.first_seen >= timedelta(hours=self._config.known_after_hours):
            return "known"
        return "unknown"

    def approve(self, node_id: str) -> DeviceView:
        with self._lock, self._sessions.begin() as session:
            device = session.scalars(select(Device).where(Device.node_id == node_id)).first()
            if device is None:
                raise KeyError(node_id)
            device.trust = "approved"
            view = DeviceView.of(device)
        log.info("device approved", extra={"node_id": node_id})
        return view

    def refresh_trust(self) -> int:
        """Promote unknown -> known when due. Returns the number of changes."""
        now = self._clock()
        changed = 0
        with self._lock, self._sessions.begin() as session:
            for device in session.scalars(select(Device).where(Device.trust != "approved")):
                trust = self._trust_for(device, now)
                if trust != device.trust:
                    device.trust = trust
                    changed += 1
        return changed

    # --- reads ---------------------------------------------------------------------

    def get(self, node_id: str) -> DeviceView | None:
        with self._sessions() as session:
            d = session.scalars(select(Device).where(Device.node_id == node_id)).first()
            return DeviceView.of(d) if d else None

    def list(self) -> list[DeviceView]:
        with self._sessions() as session:
            rows = session.scalars(select(Device).order_by(Device.first_seen)).all()
            return [DeviceView.of(d) for d in rows]

    def resolve(self, mac: str | None = None, ip: str | None = None) -> str | None:
        """node_id for a MAC or IP, without creating anything."""
        with self._sessions() as session:
            if mac:
                ident = self._hasher.device_id(mac)
                d = session.scalars(select(Device).where(Device.identity_hmac == ident)).first()
                if d:
                    return d.node_id
            ip = _valid_ip(ip)
            if ip:
                d = session.scalars(
                    select(Device).where(Device.ip == ip).order_by(Device.last_seen.desc())
                ).first()
                if d:
                    return d.node_id
        return None


def _svc(stored: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in stored.items() if k != "port_proto"}
