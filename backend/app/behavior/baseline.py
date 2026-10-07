"""Per-device and fleet baselines (one Welford accumulator per feature).

Cold start: a device with fewer than ``min_windows`` clean windows is scored
against the fleet baseline (all devices' clean windows), and results say so.
If the fleet baseline is also immature, no z-scores are produced. The anomaly
score then relies on the Isolation Forest alone, and rules still apply.

Scale: statistics are kept on log1p(x), so a z-score measures a *ratio* change.
Rates, counts and byte sizes are heavy-tailed and periodic: a single 900-byte
HTTPS call in a window of 90-byte MQTT publishes multiplies byte variance
~1000x. On a linear scale that reads as an extreme outlier; on a log scale it
is a moderate, recurring shift that the baseline absorbs. This is the same
transform the Isolation Forest uses.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Literal

from app.behavior.config import BaselineConfig
from app.behavior.features import FEATURES, Vector
from app.behavior.welford import Welford

BaselineSource = Literal["device", "fleet", "none"]

# z-scores on these are meaningless or handled by rules instead.
_NO_Z = {"new_protocols"}
# A sample variance from a handful of events is mostly sampling noise (one large
# packet among two small ones swings it by orders of magnitude), so variance
# features are neither learned nor scored below this many events per window.
VARIANCE_FEATURES = {"bytes_var"}
MIN_EVENTS_FOR_VARIANCE = 5


def scale(x: float) -> float:
    return math.log1p(max(0.0, float(x)))


@dataclass
class Baseline:
    stats: dict[str, Welford] = field(default_factory=lambda: {f: Welford() for f in FEATURES})
    protocols: set[str] = field(default_factory=set)
    windows: int = 0

    def update(self, vector: Vector, protocols: set[str], events: int = 1_000_000) -> None:
        for name in FEATURES:
            if name in vector and _usable(name, events):
                self.stats[name].add(scale(vector[name]))
        self.protocols |= protocols
        self.windows += 1

    def zscores(
        self, vector: Vector, cfg: BaselineConfig, events: int = 1_000_000
    ) -> dict[str, float]:
        return {
            name: round(
                self.stats[name].zscore(
                    scale(vector[name]), rel_floor=cfg.rel_floor, abs_floor=cfg.abs_floor
                ),
                4,
            )
            for name in FEATURES
            if name in vector
            and name not in _NO_Z
            and _usable(name, events)
            and self.stats[name].n > 0
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "windows": self.windows,
            "protocols": sorted(self.protocols),
            "stats": {k: w.to_dict() for k, w in self.stats.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Baseline:
        b = cls()
        b.windows = int(d.get("windows", 0))
        b.protocols = set(d.get("protocols", []))
        for k, v in d.get("stats", {}).items():
            if k in b.stats:
                b.stats[k] = Welford.from_dict(v)
        return b


def _usable(name: str, events: int) -> bool:
    return name not in VARIANCE_FEATURES or events >= MIN_EVENTS_FOR_VARIANCE


@dataclass
class BaselineView:
    source: BaselineSource
    cold_start: bool
    zscores: dict[str, float]
    windows: int


def choose(
    device: Baseline,
    fleet: Baseline,
    vector: Vector,
    cfg: BaselineConfig,
    events: int = 1_000_000,
) -> BaselineView:
    if device.windows >= cfg.min_windows:
        return BaselineView("device", False, device.zscores(vector, cfg, events), device.windows)
    if fleet.windows >= cfg.fleet_min_windows:
        return BaselineView("fleet", True, fleet.zscores(vector, cfg, events), device.windows)
    return BaselineView("none", True, {}, device.windows)
