"""Anomaly scoring: per-device z-scores + Isolation Forest, combined and explained.

Isolation Forest
----------------
Trained on *normal* traffic windows (log1p-transformed features: rates and
byte counts are heavy-tailed). Its anomaly score is s = -score_samples(x)
(Liu et al.'s score, in (0, 1]; about 0.5 is normal and values toward 1 are
anomalous). It is calibrated against the training distribution: p50 and p99
are stored with the model.

Model integrity: joblib files are pickles, and loading a tampered pickle runs
code. The model bytes are HMAC-SHA256 signed with the platform key and
verified *before* deserialization.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.behavior.baseline import BaselineView
from app.behavior.config import AnomalyConfig
from app.behavior.features import FEATURES, Vector

log = logging.getLogger(__name__)

MODEL_FILE = "iforest.joblib"
META_FILE = "iforest.json"


class ModelIntegrityError(RuntimeError):
    pass


def _row(vector: Vector) -> list[float]:
    return [math.log1p(max(0.0, float(vector.get(f, 0.0)))) for f in FEATURES]


@dataclass
class IForestModel:
    model: Any
    p50: float
    p99: float
    meta: dict[str, Any]

    def score(self, vector: Vector) -> float:
        return self.score_many([vector])[0]

    def score_many(self, vectors: Sequence[Vector]) -> list[float]:
        # One call for many rows: scikit-learn's per-call overhead (joblib dispatch
        # per tree) dominates single-row scoring.
        if not vectors:
            return []
        return [float(s) for s in -self.model.score_samples([_row(v) for v in vectors])]

    @classmethod
    def train(cls, vectors: Sequence[Vector], *, n_estimators: int, seed: int) -> IForestModel:
        from sklearn.ensemble import IsolationForest  # lab extra, lazy

        rows = [_row(v) for v in vectors]
        model = IsolationForest(n_estimators=n_estimators, random_state=seed, contamination="auto")
        model.fit(rows)
        scores = sorted(float(s) for s in -model.score_samples(rows))
        p50 = scores[len(scores) // 2]
        p99 = scores[min(len(scores) - 1, int(len(scores) * 0.99))]
        meta = {
            "features": list(FEATURES),
            "n_samples": len(rows),
            "n_estimators": n_estimators,
            "seed": seed,
            "p50": p50,
            "p99": p99,
            "trained_at": datetime.now(UTC).isoformat(),
        }
        return cls(model, p50, p99, meta)

    def save(self, directory: Path, key: bytes) -> None:
        import joblib

        directory.mkdir(parents=True, exist_ok=True)
        buf = io.BytesIO()
        joblib.dump(self.model, buf)
        blob = buf.getvalue()
        meta = {
            **self.meta,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "hmac_sha256": hmac.new(key, blob, hashlib.sha256).hexdigest(),
        }
        (directory / MODEL_FILE).write_bytes(blob)
        (directory / META_FILE).write_text(json.dumps(meta, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path, key: bytes) -> IForestModel:
        import joblib

        blob = (directory / MODEL_FILE).read_bytes()
        meta = json.loads((directory / META_FILE).read_text(encoding="utf-8"))
        expected = hmac.new(key, blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(meta.get("hmac_sha256", ""))):
            raise ModelIntegrityError("model signature mismatch: refusing to unpickle")
        if meta.get("features") != list(FEATURES):
            raise ModelIntegrityError("model was trained on a different feature set")
        return cls(joblib.load(io.BytesIO(blob)), float(meta["p50"]), float(meta["p99"]), meta)


class FeatureContribution(BaseModel):
    feature: str
    value: float
    z: float


class AnomalyResult(BaseModel):
    combined: float
    is_anomaly: bool
    z_component: float | None
    if_component: float | None
    if_score: float | None
    max_abs_z: float | None
    baseline: str
    cold_start: bool
    top_features: list[FeatureContribution]
    zscores: dict[str, float]


class AnomalyScorer:
    def __init__(self, cfg: AnomalyConfig, model: IForestModel | None) -> None:
        self.cfg = cfg
        self.model = model

    def if_scores(self, vectors: Sequence[Vector]) -> list[float | None]:
        if self.model is None:
            return [None] * len(vectors)
        return list(self.model.score_many(vectors))

    def score(
        self, vector: Vector, view: BaselineView, if_raw: float | None = None
    ) -> AnomalyResult:
        weights = self.cfg.weights
        parts: list[tuple[float, float]] = []
        z_comp = max_z = None
        if view.zscores:
            max_z = max(abs(z) for z in view.zscores.values())
            z_comp = min(1.0, max_z / self.cfg.z_saturation)
            parts.append((weights["zscore"], z_comp))
        if_comp = None
        if self.model is not None:
            if if_raw is None:
                if_raw = self.model.score(vector)
            spread = max(self.model.p99 - self.model.p50, 1e-6)
            if_comp = min(1.0, max(0.0, (if_raw - self.model.p50) / (2 * spread)))
            parts.append((weights["iforest"], if_comp))
        total_w = sum(w for w, _ in parts)
        combined = sum(w * c for w, c in parts) / total_w if total_w else 0.0
        top = sorted(view.zscores.items(), key=lambda kv: -abs(kv[1]))[:3]
        return AnomalyResult(
            combined=round(combined, 4),
            is_anomaly=combined >= self.cfg.threshold,
            z_component=None if z_comp is None else round(z_comp, 4),
            if_component=None if if_comp is None else round(if_comp, 4),
            if_score=None if if_raw is None else round(if_raw, 4),
            max_abs_z=None if max_z is None else round(max_z, 4),
            baseline=view.source,
            cold_start=view.cold_start,
            top_features=[
                FeatureContribution(feature=f, value=round(vector[f], 4), z=z)
                for f, z in top
                if abs(z) > 0
            ],
            zscores=view.zscores,
        )
