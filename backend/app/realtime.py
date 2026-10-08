"""Socket.IO bridge: event bus -> dashboard, batched, resumable.

* **Batching.** Bus handlers run on whatever thread published the event; they
  only append to a bounded queue. One asyncio task flushes it every
  ``FLUSH_SECONDS`` as a single ``events`` message (a list), so a burst of
  thousands of events is a handful of messages and the client renders once per
  batch instead of once per event.
* **Resume.** Clients connect with ``auth = {"token": ..., "after_seq": N}``. The
  server replays everything it still holds after ``N`` (the bus ring buffer).
  If ``N`` is older than the buffer, it sends ``resync`` so the client reloads
  its snapshot over REST instead of silently missing events.
* **Auth.** The same rules as REST reads (``app.core.auth``): a valid token, or
  anonymous only when reads don't require auth.

Lab mode only: a serverless function (hosted mode) can't hold sockets.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from collections import deque
from typing import Any

import socketio

from app.core.auth import AuthError, verify_token
from app.core.config import Settings
from app.core.events import Event, EventBus

log = logging.getLogger(__name__)

FLUSH_SECONDS = 0.1
MAX_BATCH = 1000
QUEUE_LIMIT = 50_000  # beyond this, drop oldest (clients resync via `seq` gaps)
SOCKET_PATH = "api/socket.io"


class RealtimeHub:
    def __init__(self, bus: EventBus, settings: Settings) -> None:
        self.bus = bus
        self.settings = settings
        self.sio = socketio.AsyncServer(
            async_mode="asgi",
            cors_allowed_origins=list(settings.cors_origins),
            ping_interval=20,
            ping_timeout=20,
            max_http_buffer_size=64 * 1024,  # clients only send tiny control messages
        )
        self._queue: deque[dict[str, Any]] = deque(maxlen=QUEUE_LIMIT)
        self._lock = threading.Lock()
        self._task: asyncio.Task[None] | None = None
        self._unsubscribe = bus.subscribe(self._on_event)
        self.sent_batches = 0
        self.sio.on("connect", self._connect)
        self.sio.on("disconnect", self._disconnect)

    # --- bus side (any thread) ---------------------------------------------------
    def _on_event(self, event: Event) -> None:
        with self._lock:
            self._queue.append(event.model_dump(mode="json"))

    # --- socket side (event loop) ------------------------------------------------
    async def _connect(self, sid: str, environ: dict[str, Any], auth: Any = None) -> None:
        auth = auth if isinstance(auth, dict) else {}
        token = auth.get("token")
        if token:
            try:
                principal = verify_token(self.settings, str(token))
            except AuthError as exc:
                raise socketio.exceptions.ConnectionRefusedError("unauthorized") from exc
            who = principal.actor
        elif self.settings.reads_require_auth:
            raise socketio.exceptions.ConnectionRefusedError("unauthorized")
        else:
            who = "anonymous"
        try:
            after = max(0, int(auth.get("after_seq", 0)))
        except (TypeError, ValueError):
            after = 0
        await self.sio.enter_room(sid, "live")
        held = self.bus.recent(limit=10_000)
        oldest = held[0].seq if held else None
        if after and oldest is not None and after < oldest - 1:
            await self.sio.emit("resync", {"oldest_seq": oldest}, to=sid)
        backlog = [e.model_dump(mode="json") for e in held if e.seq > after]
        for start in range(0, len(backlog), MAX_BATCH):
            await self.sio.emit("events", backlog[start : start + MAX_BATCH], to=sid)
        log.info("live client connected", extra={"who": who, "replayed": len(backlog)})

    async def _disconnect(self, sid: str, *args: Any) -> None:
        log.debug("live client disconnected", extra={"sid": sid})

    async def flush(self) -> int:
        with self._lock:
            batch = list(self._queue)[:MAX_BATCH]
            for _ in range(len(batch)):
                self._queue.popleft()
        if batch:
            await self.sio.emit("events", batch, room="live")
            self.sent_batches += 1
        return len(batch)

    async def _run(self) -> None:
        while True:
            try:
                sent = await self.flush()
            except Exception:
                log.exception("live flush failed")
                sent = 0
            if sent < MAX_BATCH:  # drain bursts without waiting
                await asyncio.sleep(FLUSH_SECONDS)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run(), name="realtime")

    async def stop(self) -> None:
        self._unsubscribe()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    def asgi_app(self, other: Any) -> Any:
        return socketio.ASGIApp(self.sio, other_asgi_app=other, socketio_path=SOCKET_PATH)
