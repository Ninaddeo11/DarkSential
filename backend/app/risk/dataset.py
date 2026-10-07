"""Labelled behavior-window datasets from the seeded simulator.

Each seed produces normal fleet traffic with randomly placed attacks of five
kinds. Windows are labelled 1 if any attack event falls in them. Used to train
the supervised XGBoost model, by the ablation study, and by Phase 7.
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.behavior.config import BehaviorConfig
from app.behavior.events import TrafficEvent
from app.behavior.features import Vector, compute
from app.simulation.traffic import Labelled, TrafficSimulator, merge

ATTACKS = ("mqtt_flood", "port_scan", "brute_force", "wildcard_subscribe", "restricted_publish")
START = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class Scenario:
    seed: int
    events: list[Labelled]

    def truth(self, window_seconds: int) -> dict[tuple[str, datetime], set[str]]:
        out: dict[tuple[str, datetime], set[str]] = defaultdict(set)
        for le in self.events:
            out[(le.device, _floor(le.event.ts, window_seconds))].add(le.label)
        return out


def _floor(ts: datetime, seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, UTC)


def scenario(
    seed: int, minutes: int = 120, attacks_per_hour: int = 6, warmup_minutes: int = 35
) -> Scenario:
    """Normal traffic plus attacks placed after a warm-up (so baselines can mature)."""
    rng = random.Random(seed * 7919 + 1)
    sim = TrafficSimulator(seed=seed)
    streams = [sim.normal(START, minutes)]
    n_attacks = max(1, minutes * attacks_per_hour // 60)
    for _ in range(n_attacks):
        kind = rng.choice(ATTACKS)
        dev = rng.choice(sim.fleet)
        at = START + timedelta(
            minutes=rng.randint(warmup_minutes, minutes - 3), seconds=rng.randint(0, 50)
        )
        if kind == "mqtt_flood":
            streams.append(
                sim.mqtt_flood(
                    dev, at, minutes=rng.randint(1, 2), per_minute=rng.choice([150, 300, 500])
                )
            )
        elif kind == "port_scan":
            streams.append(sim.port_scan(dev, at, ports=rng.randint(40, 200)))
        elif kind == "brute_force":
            streams.append(sim.brute_force(dev, at, attempts=rng.randint(15, 60)))
        elif kind == "wildcard_subscribe":
            streams.append(sim.wildcard_subscribe(dev, at))
        else:
            streams.append(sim.restricted_publish(dev, at))
    return Scenario(seed, merge(*streams))


@dataclass(frozen=True)
class LabelledWindow:
    seed: int
    device: str
    window_start: datetime
    features: Vector
    label: int
    kinds: frozenset[str]


def windows(sc: Scenario, cfg: BehaviorConfig) -> list[LabelledWindow]:
    """Stateless per-window features (no baselines) with ground-truth labels."""
    buckets: dict[tuple[str, datetime], list[Labelled]] = defaultdict(list)
    for le in sc.events:
        buckets[(le.device, _floor(le.event.ts, cfg.window_seconds))].append(le)
    out = []
    for (device, ws), items in sorted(buckets.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        events: list[TrafficEvent] = [le.event for le in items]
        vector, _ = compute(events, cfg.window_seconds, cfg.mqtt.restricted_topics)
        kinds = frozenset(le.label for le in items) - {"normal"}
        out.append(LabelledWindow(sc.seed, device, ws, vector, int(bool(kinds)), kinds))
    return out
