"""Quarantine state and the tamper-evident audit log."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, UTCDateTime


class Quarantine(Base):
    __tablename__ = "quarantines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    status: Mapped[str] = mapped_column(String(16), index=True)  # active | released | failed
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    actor: Mapped[str] = mapped_column(String(64))
    driver: Mapped[str] = mapped_column(String(16))
    dry_run: Mapped[bool] = mapped_column(Boolean)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    released_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    release_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict[str, Any]:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class AuditEntry(Base):
    """Append-only. ``hash`` = SHA-256(prev_hash + canonical JSON of the entry), so
    any edited or deleted row breaks the chain (``verify_chain``)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32), index=True)
    node_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(16))  # ok | refused | failed | dry_run
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)

    def as_dict(self) -> dict[str, Any]:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
