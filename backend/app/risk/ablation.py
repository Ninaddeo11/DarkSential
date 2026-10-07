"""Ablation: transparent linear scorer vs XGBoost vs anomaly detectors, per window.

Every behavior window of held-out simulator seeds is scored by each method and
compared to ground truth (attack in window or not):

  rules       max severity score of rule hits (0 if none)
  zscore      z component (max|z| / z_saturation), baseline-dependent
  iforest     calibrated Isolation Forest component
  combined    the pipeline's anomaly score (z + IF)
  pipeline    what the pipeline flags: rules OR combined >= threshold (binary)
  linear      window-level linear risk: 100 * (w_rate * rate + w_proto * protocol),
              the behavior part of the transparent scorer (device/intel factors are
              constant per device and excluded so the comparison is per window)
  xgboost     supervised probability (trained on disjoint seeds)

Metrics: ROC-AUC (threshold-free ranking quality) and precision / recall / FPR
at each method's operating point. Simulated traffic only: Phase 7 repeats this
on labelled public datasets where available.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine

from app.behavior.anomaly import AnomalyScorer
from app.behavior.config import BehaviorConfig
from app.behavior.pipeline import SEVERITY_SCORE, BehaviorPipeline, train_model
from app.core.db import init_db, make_engine, make_session_factory
from app.core.events import EventBus
from app.core.identifiers import DeviceIdHasher
from app.detect.registry import DeviceRegistry, DevicesConfig
from app.detect.rules import RuleEngine
from app.risk.config import RiskConfig
from app.risk.dataset import scenario, windows
from app.risk.ml import XgbModel
from app.simulation.traffic import DEFAULT_FLEET

RATE_RULES = {"mqtt_connect_flood", "network_scan", "credential_brute_force"}
PROTOCOL_RULES = {"protocol_drift", "mqtt_wildcard_subscription", "mqtt_restricted_publish"}

OPERATING_POINTS: dict[str, tuple[str, float]] = {
    # method -> (score column, flag if score >= threshold)
    "rules": ("rules", 1e-9),
    "zscore": ("zscore", 0.6),
    "iforest": ("iforest", 0.6),
    "combined": ("combined", 0.6),
    "pipeline": ("pipeline", 1.0),
    "linear": ("linear", 10.0),
    "xgboost": ("xgboost", 0.5),
}


@dataclass
class AblationResult:
    windows: list[dict[str, Any]]
    summary: list[dict[str, Any]]
    xgb_global_importance: dict[str, float]


def _pipeline(
    cfg: BehaviorConfig, rules: RuleEngine, scorer: AnomalyScorer
) -> tuple[BehaviorPipeline, Engine]:
    engine = make_engine("sqlite://")
    init_db(engine)
    sessions = make_session_factory(engine)
    bus = EventBus(history=10)
    registry = DeviceRegistry(
        sessions, DeviceIdHasher(b"ablation-key-not-secret-0123456789"), DevicesConfig(), bus
    )
    return BehaviorPipeline(registry, cfg, rules, scorer, bus, sessions), engine


def run(
    behavior_cfg: BehaviorConfig,
    risk_cfg: RiskConfig,
    rules: RuleEngine,
    test_seeds: Sequence[int] = range(1, 11),
    train_seeds: Sequence[int] = range(100, 110),
    minutes: int = 120,
) -> AblationResult:
    train = [w for s in train_seeds for w in windows(scenario(s, minutes), behavior_cfg)]
    xgb = XgbModel.train([w.features for w in train], [w.label for w in train], seed=0)
    iforest = train_model(behavior_cfg)
    w_rate, w_proto = risk_cfg.weights["rate_anomaly"], risk_cfg.weights["protocol_anomaly"]
    names = {d.ip: d.name for d in DEFAULT_FLEET}
    rows: list[dict[str, Any]] = []
    for seed in test_seeds:
        sc = scenario(seed, minutes)
        truth = sc.truth(behavior_cfg.window_seconds)
        pipe, engine = _pipeline(behavior_cfg, rules, AnomalyScorer(behavior_cfg.anomaly, iforest))
        try:
            results = pipe.ingest([le.event for le in sc.events]) + pipe.flush()
            devices = {r.node_id: pipe.registry.get(r.node_id) for r in results}
        finally:
            engine.dispose()
        probs = xgb.predict_proba([r.features for r in results])
        for r, prob in zip(results, probs, strict=True):
            dev = devices[r.node_id]
            name = names.get(dev.ip if dev and dev.ip else "", r.node_id)
            kinds = truth.get((name, r.window_start), set()) - {"normal"}
            rule_score = max((SEVERITY_SCORE[h.severity] for h in r.rule_hits), default=0.0)
            rate = max(
                [r.anomaly.combined]
                + [SEVERITY_SCORE[h.severity] for h in r.rule_hits if h.rule_id in RATE_RULES]
            )
            proto = max(
                [0.0]
                + [SEVERITY_SCORE[h.severity] for h in r.rule_hits if h.rule_id in PROTOCOL_RULES]
            )
            if r.features.get("new_protocols", 0) > 0:
                proto = max(proto, risk_cfg.factors.new_protocol_value)
            rows.append(
                {
                    "seed": seed,
                    "device": name,
                    "window_start": r.window_start.isoformat(),
                    "label": int(bool(kinds)),
                    "kinds": ",".join(sorted(kinds)),
                    "cold_start": r.anomaly.cold_start,
                    "rules": rule_score,
                    "zscore": r.anomaly.z_component or 0.0,
                    "iforest": r.anomaly.if_component or 0.0,
                    "combined": r.anomaly.combined,
                    "pipeline": float(r.anomaly.is_anomaly or bool(r.rule_hits)),
                    "linear": round(100 * (w_rate * rate + w_proto * proto), 2),
                    "xgboost": round(prob, 6),
                }
            )
    return AblationResult(rows, summarize(rows), xgb.meta["global_importance"])


def summarize(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    from sklearn.metrics import roc_auc_score

    labels = [r["label"] for r in rows]
    out = []
    for method, (col, threshold) in OPERATING_POINTS.items():
        scores = [float(r[col]) for r in rows]
        flags = [s >= threshold for s in scores]
        tp = sum(1 for f, y in zip(flags, labels, strict=True) if f and y)
        fp = sum(1 for f, y in zip(flags, labels, strict=True) if f and not y)
        fn = sum(1 for f, y in zip(flags, labels, strict=True) if not f and y)
        tn = sum(1 for f, y in zip(flags, labels, strict=True) if not f and not y)
        out.append(
            {
                "method": method,
                "roc_auc": round(float(roc_auc_score(labels, scores)), 4),
                "threshold": threshold,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
                "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
                "fpr": round(fp / (fp + tn), 6) if fp + tn else 0.0,
            }
        )
    return out


def recall_by_attack(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per attack kind: share of attack windows each method flags at its operating point."""
    kinds = sorted({k for r in rows for k in r["kinds"].split(",") if k})
    out = []
    for kind in kinds:
        subset = [r for r in rows if kind in r["kinds"].split(",")]
        entry: dict[str, Any] = {"attack": kind, "windows": len(subset)}
        for method, (col, threshold) in OPERATING_POINTS.items():
            entry[method] = round(sum(float(r[col]) >= threshold for r in subset) / len(subset), 3)
        out.append(entry)
    return out
