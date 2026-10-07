"""Mosquitto broker log -> TrafficEvents (MQTT-specific behavior features).

The broker is the only place that sees every client's CONNECT, authentication
failure, SUBSCRIBE and denied PUBLISH, including over TLS. Formats below were
captured from eclipse-mosquitto 2.0.22 with ``log_type subscribe`` + ``debug``
and ``connection_messages true``::

  <ts>: New connection from 172.17.0.1:51962 on port 8883.
  <ts>: New client connected from 172.17.0.1:51962 as status-node
         (p2, c1, k30, u'status-node').        (one line in the real log)
  <ts>: Client esp32-bad disconnected, not authorised.
  <ts>: status-node 1 dsn/cmd/status-node                  (log_type subscribe)
  <ts>: Received PUBLISH from esp32-node (d0, q1, r0, m1, 'dsn/telemetry/esp32-node',
         ... (13 bytes))                       (one line in the real log)
  <ts>: Denied PUBLISH from rogue-sensor (d0, q1, r0, m3, 'dsn/cmd/status-node',
         ... (18 bytes))                       (one line in the real log)

The line after "New connection from <ip>" carries the outcome for that socket,
so the parser remembers the last connecting IP and maps client ids to IPs.
Client ids and topics are attacker-chosen: they are length-capped and pass
through TrafficEvent/MqttInfo validation. A malformed line is skipped, never fatal.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from app.behavior.events import MqttInfo, TrafficEvent

log = logging.getLogger(__name__)

_TS = r"(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d): "
_IP = r"(?P<ip>[0-9a-fA-F:.]+?):(?P<port>\d+)"
_NEW_CONN = re.compile(_TS + r"New connection from " + _IP + r" on port (?P<lport>\d+)\.$")
_CONNECTED = re.compile(
    _TS + r"New client connected from " + _IP + r" as (?P<cid>\S{1,128}) \((?P<flags>[^)]*)\)\.$"
)
_NOT_AUTH = re.compile(_TS + r"Client (?P<cid>\S{1,128}) disconnected, not authorised\.$")
_SUB = re.compile(_TS + r"(?P<cid>\S{1,128}) (?P<qos>[012]) (?P<topic>\S{1,512})$")
_PUB = re.compile(
    _TS + r"(?P<kind>Received|Denied) PUBLISH from (?P<cid>\S{1,128}) \(d\d, q\d, r\d, m\d+, "
    r"'(?P<topic>[^']{0,512})', \.\.\. \((?P<bytes>\d+) bytes\)\)$"
)
_USER = re.compile(r"u'(?P<user>[^']{1,64})'")


class BrokerLogParser:
    def __init__(
        self, broker_ip: str | None = None, ignore_clients: frozenset[str] = frozenset()
    ) -> None:
        # Service accounts (the backend itself) legitimately subscribe with
        # wildcards and publish commands; their activity is not device behavior.
        self.broker_ip = broker_ip
        self.ignore = ignore_clients
        self._ip_by_client: dict[str, str] = {}
        self._last_conn_ip: str | None = None

    @staticmethod
    def _ts(raw: str) -> datetime:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)

    def _event(
        self, ts: str, ip: str | None, ok: bool | None, mqtt: MqttInfo, size: int = 0
    ) -> TrafficEvent:
        return TrafficEvent(
            ts=self._ts(ts),
            src_ip=ip,
            dst_ip=self.broker_ip,
            dst_port=8883,
            proto="mqtt",
            bytes=size,
            ok=ok,
            mqtt=mqtt,
        )

    def parse(self, line: str) -> TrafficEvent | None:
        line = line.rstrip("\r\n")[:1024]
        try:
            if m := _NEW_CONN.match(line):
                self._last_conn_ip = m["ip"]
                return None
            if m := _CONNECTED.match(line):
                user = _USER.search(m["flags"])
                if m["cid"] in self.ignore or (user and user["user"] in self.ignore):
                    self._ip_by_client.pop(m["cid"], None)
                    return None
                self._ip_by_client[m["cid"]] = m["ip"]
                return self._event(
                    m["ts"],
                    m["ip"],
                    True,
                    MqttInfo(packet="CONNECT", client_id=user["user"] if user else m["cid"]),
                )
            if m := _NOT_AUTH.match(line):
                ip = self._last_conn_ip
                return self._event(
                    m["ts"], ip, False, MqttInfo(packet="CONNECT", client_id=m["cid"])
                )
            if m := _PUB.match(line):
                ip = self._ip_by_client.get(m["cid"])
                if ip is None:
                    return None
                denied = m["kind"] == "Denied"
                return self._event(
                    m["ts"],
                    ip,
                    False if denied else None,
                    MqttInfo(packet="PUBLISH", topic=m["topic"], client_id=m["cid"]),
                    int(m["bytes"]),
                )
            if (m := _SUB.match(line)) and m["cid"] in self._ip_by_client:
                return self._event(
                    m["ts"],
                    self._ip_by_client[m["cid"]],
                    None,
                    MqttInfo(packet="SUBSCRIBE", topic=m["topic"], client_id=m["cid"]),
                )
        except ValueError:  # validation of attacker-controlled fields failed
            log.debug("unparseable broker log line")
        return None


class BrokerLogTailer:
    """Follows the broker log file (handles truncation/rotation) on a daemon thread."""

    def __init__(
        self,
        path: Path,
        parser: BrokerLogParser,
        sink: Callable[[list[TrafficEvent]], object],
        poll_seconds: float = 1.0,
        from_start: bool = False,
    ) -> None:
        self.path = path
        self.parser = parser
        self.sink = sink
        self.poll = poll_seconds
        self.from_start = from_start
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def read_available(self, fh: object) -> list[TrafficEvent]:
        events = []
        for line in fh:  # type: ignore[attr-defined]
            ev = self.parser.parse(line)
            if ev is not None:
                events.append(ev)
        return events

    def _run(self) -> None:
        inode = None
        fh = None
        while not self._stop.is_set():
            try:
                stat = self.path.stat()
                if (
                    fh is None
                    or (inode is not None and stat.st_ino != inode)
                    or fh.tell() > stat.st_size
                ):
                    if fh is not None:
                        fh.close()
                    fh = self.path.open("r", encoding="utf-8", errors="replace")
                    if not self.from_start and inode is None:
                        fh.seek(0, 2)  # first open: start at the end
                    inode = stat.st_ino
                events = self.read_available(fh)
                if events:
                    self.sink(events)
            except FileNotFoundError:
                pass
            except Exception:
                log.exception("broker log tailing failed")
            self._stop.wait(self.poll)
        if fh is not None:
            fh.close()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="broker-log")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


def tail_once(path: Path, parser: BrokerLogParser) -> list[TrafficEvent]:
    """Parse a whole log file (replay / tests)."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return BrokerLogTailer(path, parser, lambda e: None).read_available(fh)
