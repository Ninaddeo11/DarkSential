"""Quarantine / recovery orchestration.

Desired state lives in the ``quarantines`` table. The firewall (driver) is made
to match it: on every change, and wholesale at startup (``reconcile``).
Recovery is a persistent scheduler job per quarantine, plus a periodic sweep
as a safety net (a missed job can never leave a device quarantined forever).

Refusals (protected host, outside the lab, too many active quarantines) are
audited and emitted, never silent. Every state change writes a hash-chained
audit entry and an event:

  QUARANTINE_STARTED -> (driver) -> QUARANTINE_COMPLETED{ok}
  RECOVERY_STARTED   -> (driver) -> DEVICE_RESTORED
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.events import Event, EventBus
from app.detect.registry import DeviceRegistry
from app.models.response import Quarantine
from app.mqtt.commands import StatusNodeCommander
from app.response.audit import AuditLog
from app.response.drivers import DriverError, ResponseDriver

log = logging.getLogger(__name__)

ScheduleHook = Callable[[int, datetime], None]
CancelHook = Callable[[int], None]


class QuarantineRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ResponseService:
    def __init__(
        self,
        settings: Settings,
        driver: ResponseDriver,
        sessions: sessionmaker[Session],
        registry: DeviceRegistry,
        bus: EventBus,
        audit: AuditLog,
        commander: StatusNodeCommander,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.settings = settings
        self.driver = driver
        self.sessions = sessions
        self.registry = registry
        self.bus = bus
        self.audit = audit
        self.commander = commander
        self.clock = clock
        self.schedule_recovery: ScheduleHook | None = None
        self.cancel_recovery: CancelHook | None = None
        self._lock = threading.RLock()

    @property
    def dry_run(self) -> bool:
        return self.driver.name == "dryrun"

    # --- policy ----------------------------------------------------------------------

    def _protected_ips(self) -> set[str]:
        ips = {ipaddress.ip_address(h).compressed for h in self.settings.protected_hosts}
        for host in (self.settings.mqtt_host,):
            with contextlib.suppress(ValueError):  # a hostname, not an IP
                ips.add(ipaddress.ip_address(host or "").compressed)
        return ips

    def _check_allowed(self, ip: str, active_count: int) -> None:
        addr = ipaddress.ip_address(ip)
        if addr.compressed in self._protected_ips():
            raise QuarantineRefused("protected host (gateway/broker/admin allowlist)")
        if addr not in self.settings.lab_cidr:
            raise QuarantineRefused(f"{addr} is outside the lab network")
        if active_count >= self.settings.max_active_quarantines:
            raise QuarantineRefused(
                f"limit of {self.settings.max_active_quarantines} active quarantines reached"
            )

    # --- quarantine ------------------------------------------------------------------

    def quarantine(
        self,
        node_id: str,
        reason: str,
        *,
        actor: str,
        minutes: int | None = None,
        evidence: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        now = now or self.clock()
        minutes = minutes or self.settings.quarantine_minutes
        device = self.registry.get(node_id)
        if device is None:
            raise KeyError(node_id)
        with self._lock:
            with self.sessions() as session:
                existing = session.scalars(
                    select(Quarantine).where(
                        Quarantine.node_id == node_id, Quarantine.status == "active"
                    )
                ).first()
                active_count = len(
                    session.scalars(
                        select(Quarantine.id).where(Quarantine.status == "active")
                    ).all()
                )
            expires = now + timedelta(minutes=minutes)
            if existing is not None:
                return self._extend(existing.id, expires, actor, reason, now)
            try:
                if not device.ip:
                    raise QuarantineRefused("device has no known IP address")
                self._check_allowed(device.ip, active_count)
            except QuarantineRefused as refusal:
                self.audit.record(
                    actor,
                    "quarantine",
                    outcome="refused",
                    node_id=node_id,
                    details={"reason": reason, "refusal": refusal.reason, "ip": device.ip},
                    ts=now,
                )
                self.bus.emit(
                    "QUARANTINE_COMPLETED", node_id, ts=now, ok=False, refused=refusal.reason
                )
                raise
            self.bus.emit(
                "QUARANTINE_STARTED",
                node_id,
                ts=now,
                ip=device.ip,
                reason=reason,
                minutes=minutes,
                actor=actor,
                dry_run=self.dry_run,
            )
            with self.sessions.begin() as session:
                row = Quarantine(
                    node_id=node_id,
                    ip=device.ip,
                    status="active",
                    reason=reason,
                    evidence=evidence or {},
                    actor=actor[:64],
                    driver=self.driver.name,
                    dry_run=self.dry_run,
                    started_at=now,
                    expires_at=expires,
                )
                session.add(row)
                session.flush()
                qid = row.id
            try:
                self.driver.quarantine(device.ip)
            except DriverError as exc:
                with self.sessions.begin() as session:
                    failed = session.get(Quarantine, qid)
                    if failed is not None:  # just inserted; defensive only
                        failed.status = "failed"
                self.audit.record(
                    actor,
                    "quarantine",
                    outcome="failed",
                    node_id=node_id,
                    details={"error": str(exc), "ip": device.ip},
                    ts=now,
                )
                self.bus.emit("QUARANTINE_COMPLETED", node_id, ts=now, ok=False, error=str(exc))
                raise
            self.audit.record(
                actor,
                "quarantine",
                outcome="dry_run" if self.dry_run else "ok",
                node_id=node_id,
                ts=now,
                details={
                    "quarantine_id": qid,
                    "ip": device.ip,
                    "reason": reason,
                    "expires_at": expires.isoformat(),
                    "driver": self.driver.name,
                    "evidence": evidence or {},
                },
            )
            if self.schedule_recovery:
                self.schedule_recovery(qid, expires)
            cmd = self.commander.send("QUARANTINE", node_id, (evidence or {}).get("level"))
            self.bus.emit(
                "QUARANTINE_COMPLETED",
                node_id,
                ts=now,
                ok=True,
                quarantine_id=qid,
                ip=device.ip,
                expires_at=expires.isoformat(),
                dry_run=self.dry_run,
                command_id=cmd["id"],
            )
            return self.get(qid)

    def _extend(
        self, qid: int, expires: datetime, actor: str, reason: str, now: datetime
    ) -> dict[str, Any]:
        with self.sessions.begin() as session:
            row = session.get(Quarantine, qid)
            if row is None:
                raise KeyError(qid)
            if expires <= row.expires_at:
                return row.as_dict()
            previous = row.expires_at
            row.expires_at = expires
        self.audit.record(
            actor,
            "extend",
            node_id=row.node_id,
            ts=now,
            details={
                "quarantine_id": qid,
                "from": previous.isoformat(),
                "to": expires.isoformat(),
                "reason": reason,
            },
        )
        if self.schedule_recovery:
            self.schedule_recovery(qid, expires)
        return self.get(qid)

    # --- recovery --------------------------------------------------------------------

    def release(
        self, qid: int, *, actor: str, reason: str, now: datetime | None = None
    ) -> dict[str, Any]:
        now = now or self.clock()
        with self._lock:
            with self.sessions() as session:
                row = session.get(Quarantine, qid)
                if row is None:
                    raise KeyError(qid)
                if row.status != "active":
                    return row.as_dict()  # idempotent
                node_id, ip = row.node_id, row.ip
            self.bus.emit(
                "RECOVERY_STARTED", node_id, ts=now, quarantine_id=qid, actor=actor, reason=reason
            )
            try:
                self.driver.release(ip)
            except DriverError as exc:
                self.audit.record(
                    actor,
                    "release",
                    outcome="failed",
                    node_id=node_id,
                    ts=now,
                    details={"quarantine_id": qid, "error": str(exc)},
                )
                raise
            with self.sessions.begin() as session:
                row = session.get(Quarantine, qid)
                if row is None:
                    raise KeyError(qid)
                row.status, row.released_at = "released", now
                row.released_by, row.release_reason = actor[:64], reason
            self.audit.record(
                actor,
                "release",
                outcome="dry_run" if self.dry_run else "ok",
                node_id=node_id,
                ts=now,
                details={"quarantine_id": qid, "ip": ip, "reason": reason},
            )
            if self.cancel_recovery:
                self.cancel_recovery(qid)
            self.commander.send("RECOVER", node_id)
            self.bus.emit("DEVICE_RESTORED", node_id, ts=now, quarantine_id=qid, ip=ip)
            return self.get(qid)

    def release_node(self, node_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        with self.sessions() as session:
            row = session.scalars(
                select(Quarantine).where(
                    Quarantine.node_id == node_id, Quarantine.status == "active"
                )
            ).first()
        if row is None:
            raise KeyError(node_id)
        return self.release(row.id, actor=actor, reason=reason)

    def expire_due(self, now: datetime | None = None) -> int:
        now = now or self.clock()
        with self.sessions() as session:
            due = [
                q.id
                for q in session.scalars(
                    select(Quarantine).where(
                        Quarantine.status == "active", Quarantine.expires_at <= now
                    )
                )
            ]
        for qid in due:
            self.release(qid, actor="system:auto-recovery", reason="quarantine expired", now=now)
        return len(due)

    # --- reconciliation --------------------------------------------------------------

    def reconcile(self, now: datetime | None = None) -> dict[str, Any]:
        """Make the firewall match the DB. Runs at startup."""
        now = now or self.clock()
        expired = self.expire_due(now)
        with self.sessions() as session:
            desired = {
                q.ip
                for q in session.scalars(select(Quarantine).where(Quarantine.status == "active"))
            }
        try:
            actual = self.driver.active()
            self.driver.ensure_ready(desired)  # atomic replace seeded with desired state
            after = self.driver.active()
        except DriverError as exc:
            self.audit.record(
                "system:reconcile",
                "reconcile",
                outcome="failed",
                ts=now,
                details={"error": str(exc)},
            )
            raise
        diff = {
            "desired": sorted(desired),
            "added": sorted(desired - actual),
            "removed": sorted(actual - desired),
            "expired_released": expired,
            "in_sync": after == desired,
        }
        self.audit.record(
            "system:reconcile",
            "reconcile",
            outcome="ok" if diff["in_sync"] else "failed",
            ts=now,
            details=diff,
        )
        return diff

    # --- automatic policy ------------------------------------------------------------

    def on_event(self, event: Event) -> None:
        if event.type != "RISK_UPDATED" or not event.node_id:
            return
        action = event.payload.get("action")
        level = event.payload.get("level")
        if action in {"alert", "review_quarantine"} and level in {"high", "critical"}:
            self.commander.send("ALERT", event.node_id, level)
        if action != "quarantine" or not self.settings.auto_quarantine:
            return
        released = self._recent_operator_release(event.node_id, event.ts)
        if released is not None:
            self.audit.record(
                "system:risk-engine",
                "quarantine",
                outcome="skipped",
                node_id=event.node_id,
                ts=event.ts,
                details={
                    "reason": "operator released this device recently",
                    "released_by": released["released_by"],
                    "released_at": released["released_at"],
                    "score": event.payload.get("score"),
                },
            )
            return
        try:
            self.quarantine(
                event.node_id,
                f"automatic: risk {level} ({event.payload.get('score')}/100)",
                actor="system:risk-engine",
                evidence={
                    "score": event.payload.get("score"),
                    "level": level,
                    "explanation": event.payload.get("explanation"),
                    "contributions": event.payload.get("contributions"),
                },
                now=event.ts,
            )
        except QuarantineRefused:
            pass  # audited + emitted already
        except (DriverError, KeyError):
            log.exception("automatic quarantine failed", extra={"node_id": event.node_id})

    def _recent_operator_release(self, node_id: str, now: datetime) -> dict[str, Any] | None:
        """The latest release of this device, if a human made it within the grace period."""
        grace = timedelta(minutes=self.settings.operator_release_grace_minutes)
        if not grace:
            return None
        with self.sessions() as session:
            row = session.scalars(
                select(Quarantine)
                .where(Quarantine.node_id == node_id, Quarantine.released_at.is_not(None))
                .order_by(Quarantine.released_at.desc())
                .limit(1)
            ).first()
            if row is None or row.released_at is None:
                return None
            released_at = row.released_at
            if released_at.tzinfo is None:
                released_at = released_at.replace(tzinfo=UTC)
            by = row.released_by or ""
            if by.startswith("system:") or now - released_at > grace:
                return None
            return {"released_by": by, "released_at": released_at.isoformat()}

    def on_ack(self, raw: bytes) -> None:
        acked = self.commander.handle_ack(raw)
        if acked:
            cmd = acked["command"]
            self.audit.record(
                "status-node",
                "mqtt_ack",
                node_id=cmd.get("node_id"),
                details={"command_id": cmd["id"], "cmd": cmd["cmd"], "status": acked["status"]},
            )

    # --- reads -----------------------------------------------------------------------

    def get(self, qid: int) -> dict[str, Any]:
        with self.sessions() as session:
            row = session.get(Quarantine, qid)
            if row is None:
                raise KeyError(qid)
            return row.as_dict()

    def list(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.sessions() as session:
            query = (
                select(Quarantine)
                .order_by(Quarantine.started_at.desc(), Quarantine.id.desc())
                .limit(limit)
            )
            if status:
                query = query.where(Quarantine.status == status)
            return [q.as_dict() for q in session.scalars(query)]
