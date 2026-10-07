"""Supervised XGBoost window classifier with SHAP explanations.

This runs *alongside* the linear scorer: its probability and SHAP attribution
are stored with every risk decision, but the decision itself (score, level,
action) comes from the transparent linear model. The ablation study compares
the two.

* Features: the 12 behavior features, log1p-transformed (as for the IF).
* Labels: simulated attack windows (``dataset.py``). Real-traffic performance
  must be re-established in Phase 7.
* Explanations: ``shap.TreeExplainer``, exact for tree ensembles. Values are in
  log-odds (margin) space: base_value + sum(shap) = logit(probability).
  Global importance = mean |SHAP| over the training sample.
* Storage: XGBoost's JSON model format (not a pickle), still HMAC-signed for
  integrity, like the Isolation Forest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.behavior.anomaly import ModelIntegrityError
from app.behavior.features import FEATURES, Vector

MODEL_FILE = "xgb.json"
META_FILE = "xgb.meta.json"


def row(vector: Vector) -> list[float]:
    return [math.log1p(max(0.0, float(vector.get(f, 0.0)))) for f in FEATURES]


class MlExplanation(BaseModel):
    model: str = "xgboost"
    probability: float
    base_value: float
    shap: dict[str, float]  # feature -> SHAP value (log-odds), top contributors
    features: dict[str, float]  # raw feature values for those features


@dataclass
class XgbModel:
    model: Any
    meta: dict[str, Any]
    _explainer: Any = None

    @classmethod
    def train(cls, vectors: Sequence[Vector], labels: Sequence[int], seed: int = 0) -> XgbModel:
        import numpy as np
        from xgboost import XGBClassifier

        x = np.array([row(v) for v in vectors], dtype=float)
        y = np.array(labels, dtype=int)
        if len(set(y.tolist())) < 2:
            raise ValueError("training data needs both classes")
        model = XGBClassifier(
            n_estimators=150,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            random_state=seed,
            n_jobs=1,
            eval_metric="logloss",
            tree_method="hist",
        )
        model.fit(x, y)
        inst = cls(model, {})
        sample = x[:: max(1, len(x) // 2000)]
        values = inst._shap(sample)
        importance = {f: float(np.abs(values[:, i]).mean()) for i, f in enumerate(FEATURES)}
        inst.meta = {
            "features": list(FEATURES),
            "n_samples": len(y),
            "positive_rate": round(float(y.mean()), 4),
            "seed": seed,
            "trained_at": datetime.now(UTC).isoformat(),
            "global_importance": dict(sorted(importance.items(), key=lambda kv: -kv[1])),
        }
        return inst

    def _shap(self, x: Any) -> Any:
        if self._explainer is None:
            import shap

            self._explainer = shap.TreeExplainer(self.model)
        return self._explainer.shap_values(x)

    def predict_proba(self, vectors: Sequence[Vector]) -> list[float]:
        import numpy as np

        x = np.array([row(v) for v in vectors], dtype=float)
        return [float(p) for p in self.model.predict_proba(x)[:, 1]]

    def explain(self, vector: Vector, top: int = 5) -> MlExplanation:
        import numpy as np

        x = np.array([row(vector)], dtype=float)
        values = self._shap(x)[0]
        base = self._explainer.expected_value
        base_value = float(base[0] if np.ndim(base) else base)
        order = sorted(range(len(FEATURES)), key=lambda i: -abs(values[i]))[:top]
        return MlExplanation(
            probability=round(self.predict_proba([vector])[0], 4),
            base_value=round(base_value, 4),
            shap={FEATURES[i]: round(float(values[i]), 4) for i in order},
            features={FEATURES[i]: round(float(vector.get(FEATURES[i], 0.0)), 4) for i in order},
        )

    def save(self, directory: Path, key: bytes) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / MODEL_FILE
        self.model.save_model(str(path))
        blob = path.read_bytes()
        meta = {**self.meta, "hmac_sha256": hmac.new(key, blob, hashlib.sha256).hexdigest()}
        (directory / META_FILE).write_text(json.dumps(meta, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path, key: bytes) -> XgbModel:
        from xgboost import XGBClassifier

        blob = (directory / MODEL_FILE).read_bytes()
        meta = json.loads((directory / META_FILE).read_text(encoding="utf-8"))
        expected = hmac.new(key, blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(meta.get("hmac_sha256", ""))):
            raise ModelIntegrityError("XGBoost model signature mismatch")
        if meta.get("features") != list(FEATURES):
            raise ModelIntegrityError("XGBoost model was trained on a different feature set")
        model = XGBClassifier()
        model.load_model(str(directory / MODEL_FILE))
        return cls(model, meta)


def train_default(cfg: Any, seeds: Sequence[int] = range(100, 110), minutes: int = 120) -> XgbModel:
    """Train on simulator scenarios disjoint from the evaluation seeds (1-20)."""
    from app.risk.dataset import scenario, windows

    data = [w for s in seeds for w in windows(scenario(s, minutes), cfg)]
    return XgbModel.train([w.features for w in data], [w.label for w in data], seed=0)
