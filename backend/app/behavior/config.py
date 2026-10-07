"""Behavior configuration (config/behavior.yaml)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BaselineConfig(_Strict):
    min_windows: int = Field(ge=2)
    fleet_min_windows: int = Field(ge=2)
    rel_floor: float = Field(ge=0)
    abs_floor: float = Field(gt=0)
    max_windows: int = Field(ge=2)


class IForestConfig(_Strict):
    n_estimators: int = Field(ge=10, le=2000)
    seed: int
    training_hours: int = Field(ge=1, le=24 * 30)
    training_seed: int


class AnomalyConfig(_Strict):
    z_saturation: float = Field(gt=0)
    weights: dict[str, float]
    threshold: float = Field(gt=0, le=1)
    iforest: IForestConfig

    @model_validator(mode="after")
    def _weights(self) -> AnomalyConfig:
        if set(self.weights) != {"zscore", "iforest"}:
            raise ValueError("anomaly.weights must define exactly zscore and iforest")
        if any(w < 0 for w in self.weights.values()) or sum(self.weights.values()) <= 0:
            raise ValueError("anomaly.weights must be non-negative and not all zero")
        return self


class MqttConfig(_Strict):
    restricted_topics: list[str]


class BehaviorConfig(_Strict):
    window_seconds: int = Field(ge=5, le=3600)
    baseline: BaselineConfig
    anomaly: AnomalyConfig
    mqtt: MqttConfig


def load_behavior_config(path: Path) -> BehaviorConfig:
    return BehaviorConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
