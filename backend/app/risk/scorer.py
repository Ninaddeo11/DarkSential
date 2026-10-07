"""Transparent linear risk scorer.

contribution_f = round(weight_f * value_f * 100, 2)
score          = sum(contributions)        (exactly, by construction)

With weights summing to 1 and values in [0, 1], the score lies in [0, 100] and
is monotonic non-decreasing in every factor. Property tests check all three.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel

from app.risk.config import FACTORS, LEVELS, Level, RiskConfig


class Contribution(BaseModel):
    factor: str
    value: float
    weight: float
    contribution: float


class LinearScore(BaseModel):
    score: float
    level: Level
    contributions: list[Contribution]


def level_for(score: float, cfg: RiskConfig) -> Level:
    level: Level = "low"
    for lv in LEVELS:
        if score >= cfg.thresholds[lv]:
            level = lv
    return level


def score(values: Mapping[str, float], cfg: RiskConfig) -> LinearScore:
    contributions: list[Contribution] = []
    for name in FACTORS:
        value = float(values.get(name, 0.0))
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"factor {name} out of range: {value}")
        weight = cfg.weights[name]
        contributions.append(
            Contribution(
                factor=name,
                value=round(value, 4),
                weight=weight,
                contribution=round(weight * value * 100, 2),
            )
        )
    total = round(sum(c.contribution for c in contributions), 2)
    total = min(100.0, max(0.0, total))
    return LinearScore(score=total, level=level_for(total, cfg), contributions=contributions)
