"""Commands to the status node (a virtual lab client), and its acks.

Command topic: ``dsn/cmd/status-node``. Payload (JSON)::

    {"id": "<uuid4>", "ts": <unix seconds>, "cmd": "QUARANTINE|ALERT|RECOVER|NORMAL",
     "node_id": "dev-…" | "", "level": "critical" | "", "ttl": 60, "sig": "<hex>"}

``sig`` = HMAC-SHA256(command_key, "id|ts|cmd|node_id|level|ttl"). The message is
a pipe-joined string, not JSON, so any implementation (Python, embedded C)
reproduces it identically (re-serializing JSON byte-for-byte across languages is
fragile). Every field is restricted to ``[A-Za-z0-9._:-]`` so no field can
contain the separator. The status node (``app.lab.status_node``) drops unsigned,
badly signed, stale (|now - ts| > ttl) or replayed (seen id) commands, so a
client that gets past the broker ACLs still can't drive its state.

Ack topic: ``dsn/ack/status-node``, payload ``{"id": "<command id>", "status": "ok|bad_sig|
stale|replay|bad_cmd"}``. Acks are informational (audited). They never gate
enforcement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

log = logging.getLogger(__name__)

Command = Literal["QUARANTINE", "ALERT", "RECOVER", "NORMAL"]
COMMAND_TOPIC = "dsn/cmd/status-node"
ACK_TOPIC = "dsn/ack/status-node"
SIGNED_FIELDS = ("id", "ts", "cmd", "node_id", "level", "ttl")
_SAFE = re.compile(r"^[A-Za-z0-9._:-]*$")


def signing_string(payload: dict[str, Any]) -> bytes:
    parts = []
    for field in SIGNED_FIELDS:
        value = payload.get(field)
        text = "" if value is None else str(value)
        if not _SAFE.fullmatch(text):
            raise ValueError(f"unsigned-safe characters only in {field!r}")
        parts.append(text)
    return "|".join(parts).encode("ascii")


def sign(payload: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, signing_string(payload), hashlib.sha256).hexdigest()


def verify(payload: dict[str, Any], key: bytes) -> bool:
    try:
        expected = sign(payload, key)
    except ValueError:
        return False
    return hmac.compare_digest(str(payload.get("sig", "")), expected)


class Publisher(Protocol):
    def publish(self, topic: str, payload: str, qos: int = 1) -> None: ...

    def close(self) -> None: ...


class NullPublisher:
    """Used when MQTT is not configured: records instead of sending."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def publish(self, topic: str, payload: str, qos: int = 1) -> None:
        self.sent.append((topic, payload))

    def close(self) -> None:
        return None


class StatusNodeCommander:
    def __init__(
        self,
        publisher: Publisher,
        key: bytes | None,
        ttl_seconds: int = 60,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.publisher = publisher
        self._key = key
        self._ttl = ttl_seconds
        self._clock = clock
        self.pending: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def send(
        self, cmd: Command, node_id: str | None = None, level: str | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "ts": int(self._clock().timestamp()),
            "cmd": cmd,
            "node_id": node_id or "",
            "level": level or "",
            "ttl": self._ttl,
        }
        if self._key:
            payload["sig"] = sign(payload, self._key)
        try:
            self.publisher.publish(COMMAND_TOPIC, json.dumps(payload), qos=1)
        except Exception:  # broker outage must never block enforcement
            log.exception("status-node command publish failed", extra={"cmd": cmd})
            payload["publish_error"] = True
        with self._lock:
            self.pending[payload["id"]] = payload
            if len(self.pending) > 500:
                self.pending.pop(next(iter(self.pending)))
        return payload

    def handle_ack(self, raw: bytes) -> dict[str, Any] | None:
        """Parse an ack; returns the acked command (or None if unknown/invalid)."""
        try:
            ack = json.loads(raw.decode("utf-8"))
            ack_id = str(ack["id"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            log.warning("malformed status-node ack")
            return None
        with self._lock:
            cmd = self.pending.pop(ack_id, None)
        if cmd is None:
            return None
        return {"command": cmd, "status": str(ack.get("status", "unknown"))[:32]}


class PahoPublisher:
    """paho-mqtt v2 client: TLS, credentials, background loop with reconnect backoff.

    Subscribes to the status-node ack topic plus any ``subscriptions``
    (topic filter -> handler(topic, payload)), re-subscribing on every reconnect.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        tls: bool,
        ca_file: str | None,
        on_ack: Callable[[bytes], None],
        subscriptions: dict[str, Callable[[str, bytes], object]] | None = None,
    ) -> None:
        import paho.mqtt.client as mqtt
        from paho.mqtt.enums import CallbackAPIVersion

        self._client = mqtt.Client(
            CallbackAPIVersion.VERSION2, client_id=f"dsn-backend-{uuid.uuid4().hex[:8]}"
        )
        self._client.username_pw_set(username, password)
        if tls:
            self._client.tls_set(ca_certs=ca_file)  # verifies server cert + hostname
        self._client.reconnect_delay_set(min_delay=1, max_delay=60)
        self._on_ack = on_ack
        self._subs = dict(subscriptions or {})
        matches = mqtt.topic_matches_sub

        def on_connect(client: Any, userdata: Any, flags: Any, reason: Any, props: Any) -> None:
            if not getattr(reason, "is_failure", False):
                client.subscribe(ACK_TOPIC, qos=1)
                for topic_filter in self._subs:
                    client.subscribe(topic_filter, qos=1)
            log.info("mqtt connected", extra={"reason": str(reason)})

        def on_message(client: Any, userdata: Any, msg: Any) -> None:
            payload = bytes(msg.payload[:4096])
            if msg.topic == ACK_TOPIC:
                self._on_ack(payload)
                return
            for topic_filter, handler in self._subs.items():
                if matches(topic_filter, msg.topic):
                    try:
                        handler(msg.topic, payload)
                    except Exception:
                        log.exception("mqtt handler failed", extra={"topic_filter": topic_filter})

        self._client.on_connect = on_connect
        self._client.on_message = on_message
        self._client.connect_async(host, port, keepalive=30)
        self._client.loop_start()

    def publish(self, topic: str, payload: str, qos: int = 1) -> None:
        self._client.publish(topic, payload, qos=qos)

    def connected(self) -> bool:
        return bool(self._client.is_connected())

    def close(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()
