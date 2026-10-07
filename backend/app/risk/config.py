"""Risk configuration (config/risk.yaml), validated strictly."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

Level = Literal["low", "medium", "high", "critical"]
LEVELS: tuple[Level, ...] = ("low", "medium", "high", "critical")
FACTORS: tuple[str, ...] = (
    "unknown_device",
    "rate_anomaly",
    "protocol_anomaly",
    "threat_intel",
    "vulnerable_service",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FactorParams(_Strict):
    trust_values: dict[Literal["unknown", "known", "approved"], float]
    lookback_minutes: int = Field(ge=1, le=24 * 60)
    rate_rules: list[str]
    protocol_rules: list[str]
    new_protocol_value: float = Field(ge=0, le=1)
    match_quality: dict[Literal["exact", "range", "unversioned", "any-version"], float]
    single_source_cap: float = Field(ge=0, le=1)
    single_source_min_confidence: float = Field(ge=0, le=1)
    max_hops: int = Field(ge=1, le=4)

    @model_validator(mode="after")
    def _ranges(self) -> FactorParams:
        for name, table in (
            ("trust_values", self.trust_values),
            ("match_quality", self.match_quality),
        ):
            if any(not 0 <= v <= 1 for v in table.values()):
                raise ValueError(f"{name} values must be in [0, 1]")
        if set(self.trust_values) != {"unknown", "known", "approved"}:
            raise ValueError("trust_values must define unknown, known, approved")
        if set(self.match_quality) != {"exact", "range", "unversioned", "any-version"}:
            raise ValueError("match_quality must define every match kind")
        return self


class RiskConfig(_Strict):
    weights: dict[str, float]
    thresholds: dict[Level, float]
    actions: dict[Level, str]
    factors: FactorParams

    @model_validator(mode="after")
    def _validate(self) -> RiskConfig:
        if set(self.weights) != set(FACTORS):
            raise ValueError(f"weights must define exactly {list(FACTORS)}")
        if any(w < 0 for w in self.weights.values()):
            raise ValueError("weights must be non-negative")
        total = sum(self.weights.values())
        if not math.isclose(total, 1.0, abs_tol=1e-9):
            raise ValueError(f"weights must sum to 1.0 (got {total})")
        if set(self.thresholds) != set(LEVELS) or set(self.actions) != set(LEVELS):
            raise ValueError("thresholds and actions must define low/medium/high/critical")
        values = [self.thresholds[lv] for lv in LEVELS]
        if values[0] != 0 or values != sorted(values) or len(set(values)) != len(values):
            raise ValueError("thresholds must start at 0 and strictly increase")
        if values[-1] > 100:
            raise ValueError("thresholds must be <= 100")
        return self


def load_risk_config(path: Path) -> RiskConfig:
    return RiskConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
