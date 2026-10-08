"""Property-based tests for the transparent linear risk scorer."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from app.core.config import Settings
from app.risk.config import FACTORS, RiskConfig, load_risk_config
from app.risk.scorer import level_for, score

unit = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
factor_values = st.fixed_dictionaries({f: unit for f in FACTORS})


@st.composite
def configs(draw: st.DrawFn) -> RiskConfig:
    raw = [draw(st.floats(min_value=0.0, max_value=1.0)) for _ in FACTORS]
    total = sum(raw) or 1.0
    weights = {f: r / total for f, r in zip(FACTORS, raw, strict=True)}
    if sum(raw) == 0:
        weights = {f: 1 / len(FACTORS) for f in FACTORS}
    # Absorb float error into the largest weight (>= 1/len(FACTORS)), so the sum is
    # exactly 1 and no weight can be pushed below zero.
    largest = max(weights, key=lambda f: weights[f])
    weights[largest] += 1.0 - sum(weights.values())
    base = _base()
    return RiskConfig.model_validate({**base, "weights": weights})


def _base() -> dict[str, Any]:
    from app.core.config import BACKEND_ROOT

    return load_risk_config(BACKEND_ROOT / "config" / "risk.yaml").model_dump()


@given(configs(), factor_values)
def test_score_in_range_and_contributions_sum(cfg: RiskConfig, values: dict[str, float]) -> None:
    result = score(values, cfg)
    assert 0.0 <= result.score <= 100.0
    assert round(sum(c.contribution for c in result.contributions), 2) == result.score
    for c in result.contributions:
        assert c.contribution == round(c.weight * values[c.factor] * 100, 2)
        assert c.contribution >= 0
    assert result.level == level_for(result.score, cfg)


@given(configs(), factor_values, st.sampled_from(FACTORS), unit)
def test_monotonic_in_each_factor(
    cfg: RiskConfig, values: dict[str, float], factor: str, bump: float
) -> None:
    lower = score(values, cfg).score
    raised = {**values, factor: min(1.0, values[factor] + bump)}
    assert score(raised, cfg).score >= lower
    lowered = {**values, factor: max(0.0, values[factor] - bump)}
    assert score(lowered, cfg).score <= lower


@given(configs())
def test_extremes(cfg: RiskConfig) -> None:
    assert score({f: 0.0 for f in FACTORS}, cfg).score == 0.0
    assert score({f: 0.0 for f in FACTORS}, cfg).level == "low"
    assert score({f: 1.0 for f in FACTORS}, cfg).score == pytest.approx(100.0, abs=0.06)


def test_levels_and_shipped_config(settings: Settings) -> None:
    cfg = load_risk_config(settings.risk_config_path)
    assert sum(cfg.weights.values()) == pytest.approx(1.0)
    assert [level_for(s, cfg) for s in (0, 13.09, 13.1, 19.79, 19.8, 26.39, 26.4, 100)] == [
        "low",
        "low",
        "medium",
        "medium",
        "high",
        "high",
        "critical",
        "critical",
    ]
    result = score({"threat_intel": 1.0, "vulnerable_service": 0.8}, cfg)
    assert [(c.factor, c.contribution) for c in result.contributions if c.contribution] == [
        ("threat_intel", 35.0),
        ("vulnerable_service", 20.0),
    ]
    assert (result.score, result.level) == (55.0, "critical")


@pytest.mark.parametrize("value", [-0.01, 1.01, float("nan")])
def test_out_of_range_factor_rejected(settings: Settings, value: float) -> None:
    cfg = load_risk_config(settings.risk_config_path)
    with pytest.raises(ValueError, match="out of range"):
        score({"rate_anomaly": value}, cfg)


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"weights": {"unknown_device": 0.5, "rate_anomaly": 0.5}}, "exactly"),
        ({"weights": {f: 0.3 for f in FACTORS}}, "sum to 1.0"),
        (
            {
                "weights": {
                    **{f: 0.25 for f in FACTORS[:4]},
                    FACTORS[4]: 0.0,
                    FACTORS[0]: 0.5,
                    FACTORS[1]: 0.0,
                }
            },
            None,
        ),
        ({"thresholds": {"low": 0, "medium": 50, "high": 40, "critical": 75}}, "strictly increase"),
        ({"thresholds": {"low": 5, "medium": 25, "high": 50, "critical": 75}}, "start at 0"),
        ({"thresholds": {"low": 0, "medium": 25, "high": 50, "critical": 150}}, "<= 100"),
    ],
)
def test_config_validation(patch: dict[str, Any], message: str | None) -> None:
    data = {**_base(), **patch}
    if message is None:
        weights = data["weights"]
        data["weights"] = {**weights, FACTORS[0]: weights[FACTORS[0]] - (sum(weights.values()) - 1)}
        RiskConfig.model_validate(data)
        return
    with pytest.raises(ValidationError, match=message):
        RiskConfig.model_validate(data)


def test_negative_weight_and_factor_param_validation() -> None:
    data = _base()
    data["weights"] = {**data["weights"], "unknown_device": -0.1, "rate_anomaly": 0.4}
    with pytest.raises(ValidationError, match="non-negative"):
        RiskConfig.model_validate(data)
    data = _base()
    data["factors"]["match_quality"] = {
        "exact": 1.5,
        "range": 1,
        "unversioned": 1,
        "any-version": 1,
    }
    with pytest.raises(ValidationError, match=r"\[0, 1\]"):
        RiskConfig.model_validate(data)
