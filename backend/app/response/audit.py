"""Tamper-evident, append-only audit log.

Each entry stores ``prev_hash`` and ``hash = SHA-256(prev_hash || canonical JSON)``
over (ts, actor, action, node_id, outcome, details). Editing, deleting or
reordering any row breaks every later hash, which ``verify_chain`` detects. There
is deliberately no update/delete API.

This makes tampering *detectable*, not impossible: someone with DB write access
could rewrite the whole chain. Exporting the latest hash elsewhere (logs, the
dashboard) anchors it.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.response import AuditEntry

GENESIS = "0" * 64


def _digest(
    prev: str,
    ts: datetime,
    actor: str,
    action: str,
    node_id: str | None,
    outcome: str,
    details: dict[str, Any],
) -> str:
    body = json.dumps(
        {
            "ts": ts.astimezone(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "node_id": node_id,
            "outcome": outcome,
            "details": details,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


class ChainStatus(BaseModel):
    ok: bool
    entries: int
    head: str
    first_bad_id: int | None = None


class AuditLog:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions
        self._lock = threading.Lock()

    def record(
        self,
        actor: str,
        action: str,
        *,
        outcome: str = "ok",
        node_id: str | None = None,
        details: dict[str, Any] | None = None,
        ts: datetime | None = None,
    ) -> AuditEntry:
        ts = ts or datetime.now(UTC)
        details = json.loads(json.dumps(details or {}, default=str))  # JSON-safe snapshot
        with self._lock, self._sessions.begin() as session:
            last = session.scalars(
                select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)
            ).first()
            prev = last.hash if last else GENESIS
            entry = AuditEntry(
                ts=ts,
                actor=actor[:64],
                action=action[:32],
                node_id=node_id,
                outcome=outcome,
                details=details,
                prev_hash=prev,
                hash=_digest(prev, ts, actor[:64], action[:32], node_id, outcome, details),
            )
            session.add(entry)
        return entry

    def entries(
        self, limit: int = 100, node_id: str | None = None, before_id: int | None = None
    ) -> list[dict[str, Any]]:
        with self._sessions() as session:
            query = select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit)
            if node_id:
                query = query.where(AuditEntry.node_id == node_id)
            if before_id:
                query = query.where(AuditEntry.id < before_id)
            return [e.as_dict() for e in session.scalars(query)]

    def verify_chain(self) -> ChainStatus:
        prev, count = GENESIS, 0
        with self._sessions() as session:
            for entry in session.scalars(select(AuditEntry).order_by(AuditEntry.id)):
                expected = _digest(
                    prev,
                    entry.ts,
                    entry.actor,
                    entry.action,
                    entry.node_id,
                    entry.outcome,
                    entry.details,
                )
                if entry.prev_hash != prev or entry.hash != expected:
                    return ChainStatus(ok=False, entries=count, head=prev, first_bad_id=entry.id)
                prev, count = entry.hash, count + 1
        return ChainStatus(ok=True, entries=count, head=prev)
