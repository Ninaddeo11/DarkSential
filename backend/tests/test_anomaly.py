from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.behavior.anomaly import (
    META_FILE,
    MODEL_FILE,
    AnomalyScorer,
    IForestModel,
    ModelIntegrityError,
)
from app.behavior.baseline import BaselineView
from app.behavior.config import load_behavior_config
from app.behavior.features import FEATURES
from app.behavior.pipeline import training_vectors
from app.core.config import Settings
from tests.conftest import TEST_HMAC_KEY, requires_sklearn

KEY = TEST_HMAC_KEY.encode()


@pytest.fixture(scope="module")
def model() -> IForestModel:
    pytest.importorskip("sklearn.ensemble")
    from app.core.config import BACKEND_ROOT

    cfg = load_behavior_config(BACKEND_ROOT / "config" / "behavior.yaml")
    vectors = training_vectors(cfg, seed=3, hours=2)
    return IForestModel.train(vectors, n_estimators=50, seed=1)


def test_training_vectors_deterministic(settings: Settings) -> None:
    cfg = load_behavior_config(settings.behavior_config_path)
    a = training_vectors(cfg, seed=5, hours=1)
    b = training_vectors(cfg, seed=5, hours=1)
    assert a == b
    # 4 devices x 60 one-minute windows, minus minutes where the 60 s-period plug
    # happened (with jitter) to send nothing.
    assert 4 * 55 <= len(a) <= 4 * 60
    assert set(a[0]) == set(FEATURES)


@requires_sklearn
def test_iforest_separates_attack_from_normal(model: IForestModel) -> None:
    normal = {f: 0.0 for f in FEATURES} | {
        "request_rate": 6,
        "bytes_mean": 90,
        "bytes_var": 60,
        "unique_destinations": 1,
        "unique_dst_ports": 1,
    }
    flood = normal | {"request_rate": 500, "mqtt_connect_rate": 500, "failed_attempts": 150}
    assert model.p50 < model.p99
    assert model.score(flood) > model.p99 > model.score(normal) - 0.2


@requires_sklearn
def test_model_signature_roundtrip_and_tamper(model: IForestModel, tmp_path: Path) -> None:
    model.save(tmp_path, KEY)
    loaded = IForestModel.load(tmp_path, KEY)
    probe = {f: 1.0 for f in FEATURES}
    assert loaded.score(probe) == pytest.approx(model.score(probe))
    with pytest.raises(ModelIntegrityError, match="signature"):
        IForestModel.load(tmp_path, b"k" * 32)  # wrong key
    blob = (tmp_path / MODEL_FILE).read_bytes()
    (tmp_path / MODEL_FILE).write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))
    with pytest.raises(ModelIntegrityError, match="refusing to unpickle"):
        IForestModel.load(tmp_path, KEY)


@requires_sklearn
def test_model_feature_mismatch_rejected(model: IForestModel, tmp_path: Path) -> None:
    import hashlib
    import hmac

    model.save(tmp_path, KEY)
    meta = json.loads((tmp_path / META_FILE).read_text())
    meta["features"] = ["something_else"]
    blob = (tmp_path / MODEL_FILE).read_bytes()
    meta["hmac_sha256"] = hmac.new(KEY, blob, hashlib.sha256).hexdigest()
    (tmp_path / META_FILE).write_text(json.dumps(meta))
    with pytest.raises(ModelIntegrityError, match="feature set"):
        IForestModel.load(tmp_path, KEY)


def test_missing_model_raises_file_not_found(tmp_path: Path) -> None:
    pytest.importorskip("joblib")
    with pytest.raises(FileNotFoundError):
        IForestModel.load(tmp_path, KEY)


class FakeModel:
    def __init__(self, s: float) -> None:
        self.s = s
        self.p50, self.p99 = 0.45, 0.55

    def score(self, vector: dict[str, float]) -> float:
        return self.s


def view(z: dict[str, float], source: str = "device") -> BaselineView:
    return BaselineView(source, source != "device", z, 40)  # type: ignore[arg-type]


def test_scorer_combination_math(settings: Settings) -> None:
    cfg = load_behavior_config(settings.behavior_config_path).anomaly
    vec = {f: 1.0 for f in FEATURES}
    # z only: max|z| = 3 -> 3/6 = 0.5
    r = AnomalyScorer(cfg, None).score(vec, view({"request_rate": -3.0, "dns_rate": 1.0}))
    assert (r.z_component, r.if_component, r.combined, r.is_anomaly) == (0.5, None, 0.5, False)
    assert [c.feature for c in r.top_features] == ["request_rate", "dns_rate"]
    # IF only (cold start, no baseline): s at p99 -> 0.5
    r = AnomalyScorer(cfg, FakeModel(0.55)).score(vec, view({}, "none"))  # type: ignore[arg-type]
    assert (r.z_component, r.if_component, r.combined) == (None, 0.5, 0.5)
    assert r.cold_start
    # Both, saturated
    r = AnomalyScorer(cfg, FakeModel(0.9)).score(vec, view({"request_rate": 12.0}))  # type: ignore[arg-type]
    assert (r.z_component, r.if_component, r.combined, r.is_anomaly) == (1.0, 1.0, 1.0, True)
    # IF score below the median clamps to 0
    r = AnomalyScorer(cfg, FakeModel(0.2)).score(vec, view({"request_rate": 0.0}))  # type: ignore[arg-type]
    assert (r.if_component, r.combined) == (0.0, 0.0)
    # Nothing available: zero, not an error
    r = AnomalyScorer(cfg, None).score(vec, view({}, "none"))
    assert (r.combined, r.is_anomaly) == (0.0, False)
