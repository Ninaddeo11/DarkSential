"""Typed in-process event bus.

Subsystems publish domain events; consumers (the Socket.IO bridge in Phase 6,
tests, the CLI) subscribe. A bounded ring buffer keeps recent events for the
timeline API. Handlers run synchronously in the publisher's thread; a failing
handler is logged and isolated so it can't break the publisher.

The event type names are the shared backend/frontend contract.
"""

from __future__ import annotations

import itertools
import logging
import threading
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

EventType = Literal[
    "DEVICE_CONNECTED",
    "DEVICE_PROFILED",
    "ANOMALY_DETECTED",
    "THREAT_CORRELATED",
    "RISK_UPDATED",
    "QUARANTINE_STARTED",
    "QUARANTINE_COMPLETED",
    "RECOVERY_STARTED",
    "DEVICE_RESTORED",
]

_seq = itertools.count(1)


class Event(BaseModel):
    seq: int = Field(default_factory=lambda: next(_seq))
    type: EventType
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    node_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


Handler = Callable[[Event], None]


class EventBus:
    def __init__(self, history: int = 2000) -> None:
        self._handlers: list[Handler] = []
        self._recent: deque[Event] = deque(maxlen=history)
        self._lock = threading.Lock()

    def subscribe(self, handler: Handler) -> Callable[[], None]:
        with self._lock:
            self._handlers.append(handler)

        def unsubscribe() -> None:
            with self._lock:
                if handler in self._handlers:
                    self._handlers.remove(handler)

        return unsubscribe

    def publish(self, event: Event) -> Event:
        with self._lock:
            self._recent.append(event)
            handlers = list(self._handlers)
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                log.exception("event handler failed", extra={"event_type": event.type})
        return event

    def emit(
        self,
        type_: EventType,
        node_id: str | None = None,
        *,
        ts: datetime | None = None,
        **payload: Any,
    ) -> Event:
        """Publish an event. ``ts`` is *domain* time (observation / window end);
        it defaults to now. Replays therefore stay consistent with their data."""
        event = Event(type=type_, node_id=node_id, payload=payload)
        if ts is not None:
            event.ts = ts
        return self.publish(event)

    def recent(
        self, limit: int = 100, node_id: str | None = None, after_seq: int = 0
    ) -> list[Event]:
        with self._lock:
            items = [
                e
                for e in self._recent
                if e.seq > after_seq and (node_id is None or e.node_id == node_id)
            ]
        return items[-limit:]
