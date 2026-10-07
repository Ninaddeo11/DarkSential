"""Convert packet captures into TrafficEvents ("pcap-derived events").

One event per *request*, not per packet:
* TCP: connection attempts (SYN without ACK). The port maps to a protocol name.
* MQTT over plaintext 1883: CONNECT / PUBLISH / SUBSCRIBE / PINGREQ / DISCONNECT
  parsed from the fixed header (topics included). A CONNACK with a non-zero return
  code becomes a failed CONNECT for the client. TLS (8883) payloads are opaque
  and only counted as connections.
* UDP: DNS queries (with qname), NTP and other datagrams.

Payload parsing is bounds-checked: captures come from untrusted devices.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.behavior.events import MqttInfo, MqttPacket, TrafficEvent

_TCP_PROTOS = {
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    554: "rtsp",
    1883: "mqtt",
    8883: "mqtt",
    8080: "http",
}
_UDP_PROTOS = {53: "dns", 123: "ntp", 5353: "mdns", 1900: "ssdp", 67: "dhcp", 68: "dhcp"}
_MQTT_TYPES: dict[int, MqttPacket] = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    8: "SUBSCRIBE",
    10: "UNSUBSCRIBE",
    12: "PINGREQ",
    14: "DISCONNECT",
}


def _remaining_length(buf: bytes, start: int) -> tuple[int, int] | None:
    """MQTT variable-length integer -> (value, bytes used)."""
    value, mult = 0, 1
    for i in range(4):
        if start + i >= len(buf):
            return None
        byte = buf[start + i]
        value += (byte & 0x7F) * mult
        if not byte & 0x80:
            return value, i + 1
        mult *= 128
    return None


def _utf8_field(buf: bytes, pos: int) -> str | None:
    if pos + 2 > len(buf):
        return None
    length = int.from_bytes(buf[pos : pos + 2], "big")
    raw = buf[pos + 2 : pos + 2 + length]
    if len(raw) != length:
        return None
    return raw.decode("utf-8", "replace")[:1024]


def parse_mqtt(payload: bytes) -> tuple[MqttPacket, str | None, int | None] | None:
    """Return (packet type, topic, CONNACK return code) for one MQTT control packet."""
    if len(payload) < 2:
        return None
    ptype = _MQTT_TYPES.get(payload[0] >> 4)
    if ptype is None:
        return None
    rl = _remaining_length(payload, 1)
    if rl is None:
        return None
    _, used = rl
    body = 1 + used
    if ptype == "PUBLISH":
        return ptype, _utf8_field(payload, body), None
    if ptype == "SUBSCRIBE":
        return ptype, _utf8_field(payload, body + 2), None  # skip packet id
    if ptype == "CONNACK":
        return ptype, None, payload[body + 1] if len(payload) > body + 1 else None
    return ptype, None, None


def events_from_packets(packets: Iterable[Any]) -> Iterator[TrafficEvent]:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    for pkt in packets:
        if IP not in pkt:
            continue
        ts = datetime.fromtimestamp(float(pkt.time), UTC)
        ip = pkt[IP]
        mac = pkt[Ether].src if Ether in pkt else None
        base = {"ts": ts, "src_mac": mac, "src_ip": ip.src, "dst_ip": ip.dst, "bytes": len(pkt)}
        if TCP in pkt:
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            flags = int(tcp.flags)
            if flags & 0x02 and not flags & 0x10:  # SYN, not SYN-ACK
                yield TrafficEvent(
                    **base, dst_port=tcp.dport, proto=_TCP_PROTOS.get(tcp.dport, "tcp")
                )
            elif payload and 1883 in (tcp.sport, tcp.dport):
                parsed = parse_mqtt(payload)
                if parsed is None:
                    continue
                ptype, topic, rc = parsed
                if ptype == "CONNACK":
                    if rc:  # refused: a failed CONNECT for the client (packet's dst)
                        yield TrafficEvent(
                            ts=ts,
                            src_mac=pkt[Ether].dst if Ether in pkt else None,
                            src_ip=ip.dst,
                            dst_ip=ip.src,
                            dst_port=tcp.sport,
                            proto="mqtt",
                            bytes=len(pkt),
                            ok=False,
                            mqtt=MqttInfo(packet="CONNECT"),
                        )
                    continue
                yield TrafficEvent(
                    **base,
                    dst_port=tcp.dport,
                    proto="mqtt",
                    mqtt=MqttInfo(packet=ptype, topic=topic),
                )
        elif UDP in pkt:
            udp = pkt[UDP]
            if udp.sport in _UDP_PROTOS and udp.dport not in _UDP_PROTOS:
                continue  # a service's reply to an ephemeral port is not a request
            proto = _UDP_PROTOS.get(udp.dport, "udp")
            query = None
            if proto == "dns" and DNS in pkt and not pkt[DNS].qr and pkt[DNS].qd is not None:
                qd = pkt[DNS].qd
                first = qd[0] if isinstance(qd, list) else qd
                query = bytes(first.qname).decode("utf-8", "replace").rstrip(".")[:255]
            elif proto == "dns" and DNS in pkt and pkt[DNS].qr:
                continue  # responses are not requests
            yield TrafficEvent(**base, dst_port=udp.dport, proto=proto, dns_query=query)


def events_from_pcap(path: Path) -> list[TrafficEvent]:
    from scapy.utils import PcapReader

    with PcapReader(str(path)) as reader:
        return list(events_from_packets(reader))
