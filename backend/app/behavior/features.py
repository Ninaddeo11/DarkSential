"""Per-device feature vectors over a window of traffic events.

All rates are normalized to events per minute, whatever the window length.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence

from app.behavior.events import TrafficEvent
from app.behavior.welford import Welford

FEATURES: tuple[str, ...] = (
    "request_rate",  # events / min
    "unique_destinations",  # distinct dst ip:port
    "unique_dst_ports",  # distinct dst ports (scan indicator)
    "failed_attempts",  # events with ok == False (auth/connect failures)
    "proto_entropy",  # Shannon entropy (bits) of the protocol mix
    "bytes_mean",  # mean bytes per event
    "bytes_var",  # sample variance of bytes per event
    "dns_rate",  # DNS queries / min
    "mqtt_connect_rate",  # MQTT CONNECTs / min
    "mqtt_wildcard_subs",  # SUBSCRIBEs using # or +
    "mqtt_restricted_publishes",  # PUBLISHes to restricted topics
    "new_protocols",  # protocols never seen in this device's baseline
)

Vector = dict[str, float]


def topic_matches(pattern: str, topic: str) -> bool:
    """MQTT topic filter matching (``+`` single level, ``#`` multi level)."""
    p_parts, t_parts = pattern.split("/"), topic.split("/")
    for i, part in enumerate(p_parts):
        if part == "#":
            return True
        if i >= len(t_parts) or (part != "+" and part != t_parts[i]):
            return False
    return len(p_parts) == len(t_parts)


def compute(
    events: Sequence[TrafficEvent],
    window_seconds: float,
    restricted_topics: Sequence[str],
    known_protocols: set[str] | None = None,
) -> tuple[Vector, set[str]]:
    """Return (feature vector, protocols seen in this window)."""
    per_min = 60.0 / window_seconds
    sizes = Welford()
    protos: Counter[str] = Counter()
    destinations: set[tuple[str | None, int | None]] = set()
    ports: set[int] = set()
    failed = dns = connects = wildcard = restricted = 0
    for ev in events:
        sizes.add(float(ev.bytes))
        protos[ev.proto] += 1
        if ev.dst_ip is not None or ev.dst_port is not None:
            destinations.add((ev.dst_ip, ev.dst_port))
        if ev.dst_port is not None:
            ports.add(ev.dst_port)
        if ev.ok is False:
            failed += 1
        if ev.proto == "dns" or ev.dns_query:
            dns += 1
        if ev.mqtt:
            topic = ev.mqtt.topic or ""
            if ev.mqtt.packet == "CONNECT":
                connects += 1
            elif ev.mqtt.packet == "SUBSCRIBE" and ("#" in topic or "+" in topic):
                wildcard += 1
            elif ev.mqtt.packet == "PUBLISH" and any(
                topic_matches(p, topic) for p in restricted_topics
            ):
                restricted += 1
    total = sum(protos.values())
    entropy = -sum((c / total) * math.log2(c / total) for c in protos.values()) if total else 0.0
    seen = set(protos)
    vector: Vector = {
        "request_rate": len(events) * per_min,
        "unique_destinations": float(len(destinations)),
        "unique_dst_ports": float(len(ports)),
        "failed_attempts": float(failed),
        "proto_entropy": round(entropy, 6),
        "bytes_mean": sizes.mean,
        "bytes_var": sizes.variance,
        "dns_rate": dns * per_min,
        "mqtt_connect_rate": connects * per_min,
        "mqtt_wildcard_subs": float(wildcard),
        "mqtt_restricted_publishes": float(restricted),
        "new_protocols": float(len(seen - known_protocols)) if known_protocols else 0.0,
    }
    return vector, seen
