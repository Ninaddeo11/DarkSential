"""Behavior pipeline: traffic events -> windows -> features -> scoring -> detections.

Event-time driven. Windows are tumbling, aligned to epoch multiples of
``window_seconds``, and a window closes once any event at or after its end
arrives (or on ``flush()``). Replay is therefore deterministic. Live sources
call ``tick(now)`` periodically.

Per closed window:
  features -> baseline view (device / fleet / none) -> anomaly score -> rules
  -> Detection rows + ANOMALY_DETECTED events -> learn ONLY if clean.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.behavior.anomaly import AnomalyResult, AnomalyScorer, IForestModel
from app.behavior.baseline import Baseline, choose
from app.behavior.config import BehaviorConfig
from app.behavior.events import TrafficEvent
from app.behavior.features import Vector, compute
from app.core.events import EventBus
from app.detect.observations import Observation
from app.detect.registry import DeviceRegistry
from app.detect.rules import RuleEngine, RuleHit
from app.models.device import Detection, DeviceBaseline

log = logging.getLogger(__name__)

FLEET_KEY = "__fleet__"
SEVERITY_SCORE = {"low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}


class WindowResult(BaseModel):
    node_id: str
    window_start: datetime
    window_end: datetime
    events: int
    features: Vector
    anomaly: AnomalyResult
    rule_hits: list[RuleHit]
    learned: bool


def _floor(ts: datetime, seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, UTC)


class BehaviorPipeline:
    def __init__(
        self,
        registry: DeviceRegistry,
        cfg: BehaviorConfig,
        rules: RuleEngine,
        scorer: AnomalyScorer,
        bus: EventBus,
        sessions: sessionmaker[Session],
    ) -> None:
        self.registry = registry
        self.cfg = cfg
        self.rules = rules
        self.scorer = scorer
        self.bus = bus
        self.sessions = sessions
        self._lock = threading.RLock()
        self._buffers: dict[str, list[TrafficEvent]] = defaultdict(list)
        self._window_start: dict[str, datetime] = {}
        self._baselines: dict[str, Baseline] = {}
        self.latest: dict[str, WindowResult] = {}
        self._load_baselines()

    # --- baselines -------------------------------------------------------------------

    def _load_baselines(self) -> None:
        with self.sessions() as session:
            for row in session.scalars(select(DeviceBaseline)):
                self._baselines[row.node_id] = Baseline.from_dict(row.state)

    def baseline(self, node_id: str) -> Baseline:
        return self._baselines.setdefault(node_id, Baseline())

    def _save_baselines(self, session: Session, node_ids: Iterable[str], now: datetime) -> None:
        for node_id in node_ids:
            state = self._baselines[node_id].to_dict()
            row = session.get(DeviceBaseline, node_id)
            if row is None:
                session.add(DeviceBaseline(node_id=node_id, state=state, updated_at=now))
            else:
                row.state, row.updated_at = state, now

    # --- ingestion -------------------------------------------------------------------

    def _node_for(self, ev: TrafficEvent) -> str | None:
        node_id = self.registry.resolve(mac=ev.src_mac, ip=ev.src_ip)
        if node_id:
            return node_id
        view = self.registry.observe(
            Observation(source="traffic", ts=ev.ts, mac=ev.src_mac, ip=ev.src_ip)
        )
        return view.node_id if view else None

    def ingest(self, events: Sequence[TrafficEvent]) -> list[WindowResult]:
        results: list[WindowResult] = []
        for ev in sorted(events, key=lambda e: e.ts):
            node_id = self._node_for(ev)
            if node_id is None:
                continue
            with self._lock:
                results += self._advance(ev.ts)
                start = _floor(ev.ts, self.cfg.window_seconds)
                self._window_start.setdefault(node_id, start)
                self._buffers[node_id].append(ev)
        return results

    def tick(self, now: datetime) -> list[WindowResult]:
        with self._lock:
            return self._advance(now)

    def flush(self) -> list[WindowResult]:
        with self._lock:
            far = max(self._window_start.values(), default=datetime.now(UTC))
            return self._advance(far + timedelta(seconds=self.cfg.window_seconds))

    def _advance(self, now: datetime) -> list[WindowResult]:
        width = timedelta(seconds=self.cfg.window_seconds)
        results: list[WindowResult] = []
        for node_id in sorted(self._window_start):
            start = self._window_start[node_id]
            if now < start + width:
                continue
            end = start + width
            buf = self._buffers[node_id]
            in_window = [e for e in buf if e.ts < end]
            self._buffers[node_id] = [e for e in buf if e.ts >= end]
            if in_window:
                results.append(self._close(node_id, start, end, in_window))
            remaining = self._buffers[node_id]
            if remaining:
                self._window_start[node_id] = _floor(remaining[0].ts, self.cfg.window_seconds)
            else:
                del self._window_start[node_id]
        if results:
            with self.sessions.begin() as session:
                self._persist(session, results)
        return results

    # --- scoring ---------------------------------------------------------------------

    def _close(
        self, node_id: str, start: datetime, end: datetime, events: list[TrafficEvent]
    ) -> WindowResult:
        device = self.baseline(node_id)
        fleet = self.baseline(FLEET_KEY)
        mature = device.windows >= self.cfg.baseline.min_windows
        vector, protocols = compute(
            events,
            self.cfg.window_seconds,
            self.cfg.mqtt.restricted_topics,
            known_protocols=device.protocols if mature else None,
        )
        view = choose(device, fleet, vector, self.cfg.baseline, len(events))
        anomaly = self.scorer.score(vector, view)
        hits = self.rules.evaluate(vector, view.zscores)
        clean = not anomaly.is_anomaly and not hits
        learned = False
        if clean and device.windows < self.cfg.baseline.max_windows:
            device.update(vector, protocols, len(events))
            fleet.update(vector, protocols, len(events))
            learned = True
        result = WindowResult(
            node_id=node_id,
            window_start=start,
            window_end=end,
            events=len(events),
            features=vector,
            anomaly=anomaly,
            rule_hits=hits,
            learned=learned,
        )
        self.latest[node_id] = result
        return result

    def _persist(self, session: Session, results: list[WindowResult]) -> None:
        emitted: list[tuple[str, dict[str, Any]]] = []
        for r in results:
            if r.anomaly.is_anomaly:
                summary = "Behavior anomaly: " + ", ".join(
                    f"{c.feature}={c.value:g} (z={c.z:+.1f})" for c in r.anomaly.top_features
                )
                session.add(
                    self._detection(
                        r,
                        "anomaly",
                        None,
                        "medium",
                        r.anomaly.combined,
                        [],
                        r.anomaly.model_dump(),
                        summary,
                    )
                )
                emitted.append(
                    (
                        r.node_id,
                        {
                            "kind": "anomaly",
                            "score": r.anomaly.combined,
                            "summary": summary,
                            "cold_start": r.anomaly.cold_start,
                            "window_end": r.window_end.isoformat(),
                        },
                    )
                )
            for hit in r.rule_hits:
                evidence = {"rule": hit.model_dump(), "anomaly": r.anomaly.model_dump()}
                summary = f"{hit.title}: " + ", ".join(
                    f"{e.name}{'(z)' if e.kind == 'z' else ''}="
                    f"{e.observed:g} {e.op} {e.threshold:g}"
                    for e in hit.evidence
                )
                session.add(
                    self._detection(
                        r,
                        "rule",
                        hit.rule_id,
                        hit.severity,
                        SEVERITY_SCORE[hit.severity],
                        hit.techniques,
                        evidence,
                        summary,
                    )
                )
                emitted.append(
                    (
                        r.node_id,
                        {
                            "kind": "rule",
                            "rule_id": hit.rule_id,
                            "severity": hit.severity,
                            "techniques": hit.techniques,
                            "summary": summary,
                            "window_end": r.window_end.isoformat(),
                        },
                    )
                )
        changed = {r.node_id for r in results if r.learned} | (
            {FLEET_KEY} if any(r.learned for r in results) else set()
        )
        self._save_baselines(session, changed, results[-1].window_end)
        for node_id, payload in emitted:
            self.bus.emit("ANOMALY_DETECTED", node_id, **payload)

    @staticmethod
    def _detection(
        r: WindowResult,
        kind: str,
        rule_id: str | None,
        severity: str,
        score: float,
        techniques: list[str],
        evidence: dict[str, Any],
        summary: str,
    ) -> Detection:
        return Detection(
            node_id=r.node_id,
            ts=r.window_end,
            kind=kind,
            rule_id=rule_id,
            severity=severity,
            score=score,
            techniques=techniques,
            evidence=evidence,
            window_start=r.window_start,
            window_end=r.window_end,
            summary=summary[:1000],
        )

    # --- wifi alerts -----------------------------------------------------------------

    def record_alert(
        self, node_id: str, rule_id: str, evidence: dict[str, Any], now: datetime
    ) -> None:
        rule = self.rules.by_id[rule_id]
        summary = f"{rule.title}: " + ", ".join(f"{k}={v}" for k, v in evidence.items())
        with self.sessions.begin() as session:
            session.add(
                Detection(
                    node_id=node_id,
                    ts=now,
                    kind="rule",
                    rule_id=rule_id,
                    severity=rule.severity,
                    score=SEVERITY_SCORE[rule.severity],
                    techniques=list(rule.techniques),
                    evidence={"alert": evidence, "rationale": rule.rationale},
                    window_start=now,
                    window_end=now,
                    summary=summary[:1000],
                )
            )
        self.bus.emit(
            "ANOMALY_DETECTED",
            node_id,
            kind="rule",
            rule_id=rule_id,
            severity=rule.severity,
            techniques=list(rule.techniques),
            summary=summary,
        )


def training_vectors(cfg: BehaviorConfig, seed: int, hours: int) -> list[Vector]:
    """Normal-traffic windows from the seeded simulator, for Isolation Forest training."""
    from app.simulation.traffic import TrafficSimulator

    start = datetime(2026, 1, 1, tzinfo=UTC)
    sim = TrafficSimulator(seed=seed)
    buckets: dict[tuple[str, datetime], list[TrafficEvent]] = defaultdict(list)
    for le in sim.normal(start, hours * 60):
        buckets[(le.device, _floor(le.event.ts, cfg.window_seconds))].append(le.event)
    return [
        compute(evs, cfg.window_seconds, cfg.mqtt.restricted_topics)[0]
        for _, evs in sorted(buckets.items(), key=lambda kv: (kv[0][1], kv[0][0]))
    ]


def train_model(cfg: BehaviorConfig) -> IForestModel:
    vectors = training_vectors(
        cfg, cfg.anomaly.iforest.training_seed, cfg.anomaly.iforest.training_hours
    )
    return IForestModel.train(
        vectors, n_estimators=cfg.anomaly.iforest.n_estimators, seed=cfg.anomaly.iforest.seed
    )
