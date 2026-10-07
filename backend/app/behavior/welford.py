"""Welford's online mean/variance, with Chan et al.'s parallel merge.

State is (n, mean, M2), where M2 is the running sum of squared deviations from
the current mean. Updates are numerically stable (no sum-of-squares
cancellation). Sample variance = M2 / (n - 1).
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class Welford:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, x: float) -> None:
        if not math.isfinite(x):
            raise ValueError("Welford.add requires a finite value")
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)  # uses the *updated* mean

    def merge(self, other: Welford) -> Welford:
        """Combine two independent accumulators (Chan, Golub & LeVeque 1979)."""
        if other.n == 0:
            return Welford(self.n, self.mean, self.m2)
        if self.n == 0:
            return Welford(other.n, other.mean, other.m2)
        n = self.n + other.n
        delta = other.mean - self.mean
        mean = self.mean + delta * other.n / n
        m2 = self.m2 + other.m2 + delta * delta * self.n * other.n / n
        return Welford(n, mean, m2)

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(max(self.variance, 0.0))

    def zscore(self, x: float, *, rel_floor: float = 0.0, abs_floor: float = 1e-9) -> float:
        """z = (x - mean) / effective std, where the std is floored to avoid blow-ups."""
        std = max(self.std, rel_floor * abs(self.mean), abs_floor)
        return (x - self.mean) / std

    def to_dict(self) -> dict[str, float]:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, d: dict[str, float]) -> Welford:
        return cls(int(d["n"]), float(d["mean"]), float(d["m2"]))
