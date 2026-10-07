from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import given
from hypothesis import strategies as st
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.behavior.pcap import events_from_pcap, parse_mqtt

DEV = "24:0a:c4:40:00:04"
BROKER = "b8:27:eb:00:00:02"


def mqtt_publish(topic: str, payload: bytes = b"21.5") -> bytes:
    body = len(topic).to_bytes(2, "big") + topic.encode() + payload
    return bytes([0x30, len(body)]) + body


def mqtt_subscribe(topic: str) -> bytes:
    body = b"\x00\x01" + len(topic).to_bytes(2, "big") + topic.encode() + b"\x00"
    return bytes([0x82, len(body)]) + body


def test_parse_mqtt_packets() -> None:
    assert parse_mqtt(mqtt_publish("home/t")) == ("PUBLISH", "home/t", None)
    assert parse_mqtt(mqtt_subscribe("#")) == ("SUBSCRIBE", "#", None)
    assert parse_mqtt(bytes([0x10, 0x00])) == ("CONNECT", None, None)
    assert parse_mqtt(bytes([0x20, 0x02, 0x00, 0x05])) == ("CONNACK", None, 5)
    assert parse_mqtt(bytes([0xC0, 0x00])) == ("PINGREQ", None, None)
    assert parse_mqtt(b"") is None
    assert parse_mqtt(bytes([0xF0, 0x00])) is None  # reserved type
    assert parse_mqtt(bytes([0x30, 0xFF, 0xFF, 0xFF, 0xFF])) is None  # bad length varint
    assert parse_mqtt(bytes([0x30, 0x05, 0x00, 0x09, ord("a")])) == ("PUBLISH", None, None)


@given(st.binary(max_size=64))
def test_parse_mqtt_never_crashes(blob: bytes) -> None:
    parse_mqtt(blob)


def test_pcap_to_events(tmp_path: Path) -> None:
    t = 1_790_000_000.0
    pkts: list[Any] = []

    def add(pkt: object, offset: float) -> None:
        pkt.time = t + offset  # type: ignore[attr-defined]
        pkts.append(pkt)

    base = Ether(src=DEV, dst=BROKER) / IP(src="192.168.50.24", dst="192.168.50.2")
    back = Ether(src=BROKER, dst=DEV) / IP(src="192.168.50.2", dst="192.168.50.24")
    add(base / TCP(sport=40000, dport=1883, flags="S"), 0)
    add(back / TCP(sport=1883, dport=40000, flags="SA"), 0.01)  # SYN-ACK: not a request
    add(base / TCP(sport=40000, dport=1883, flags="PA") / Raw(bytes([0x10, 0x00])), 0.02)
    add(back / TCP(sport=1883, dport=40000, flags="PA") / Raw(bytes([0x20, 2, 0, 5])), 0.03)
    add(base / TCP(sport=40000, dport=1883, flags="PA") / Raw(mqtt_publish("dsn/cmd/x")), 1)
    add(base / TCP(sport=40000, dport=1883, flags="PA") / Raw(mqtt_subscribe("#")), 2)
    add(base / TCP(sport=40000, dport=1883, flags="PA") / Raw(b"\xff\xff"), 3)  # garbage
    add(base / TCP(sport=40001, dport=23, flags="S"), 4)
    add(
        Ether(src=DEV)
        / IP(src="192.168.50.24", dst="192.168.50.1")
        / UDP(sport=5000, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="pool.ntp.org")),
        5,
    )
    add(
        Ether(src=BROKER)
        / IP(src="192.168.50.1", dst="192.168.50.24")
        / UDP(sport=53, dport=5000)
        / DNS(qr=1),
        5.1,
    )  # DNS response ignored
    add(
        Ether(src=DEV) / IP(src="192.168.50.24", dst="198.51.100.123") / UDP(sport=123, dport=123),
        6,
    )
    add(Ether(src=DEV) / Raw(b"not ip"), 7)
    path = tmp_path / "lab.pcap"
    wrpcap(str(path), pkts)

    events = events_from_pcap(path)
    summary = [
        (
            e.proto,
            e.dst_port,
            e.mqtt.packet if e.mqtt else None,
            e.mqtt.topic if e.mqtt else None,
            e.ok,
            e.dns_query,
        )
        for e in events
    ]
    assert summary == [
        ("mqtt", 1883, None, None, None, None),  # SYN
        ("mqtt", 1883, "CONNECT", None, None, None),
        ("mqtt", 1883, "CONNECT", None, False, None),  # refused CONNACK -> failed connect
        ("mqtt", 1883, "PUBLISH", "dsn/cmd/x", None, None),
        ("mqtt", 1883, "SUBSCRIBE", "#", None, None),
        ("telnet", 23, None, None, None, None),
        ("dns", 53, None, None, None, "pool.ntp.org"),
        ("ntp", 123, None, None, None, None),
    ]
    refused = events[2]
    assert refused.src_mac == DEV  # attributed to the client, not the broker
    assert refused.src_ip == "192.168.50.24"
    assert all(e.ts.timestamp() >= t for e in events)
