"""Explainable risk engine: device context -> factors -> linear score -> decision.

Every decision is machine-readable (factor, value, weight, contribution), comes
with a human-readable explanation, a recommended action, and the evidence paths
from the threat graph. The XGBoost + SHAP opinion is attached for comparison but
never changes the decision.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.behavior.pipeline import SEVERITY_SCORE, BehaviorPipeline, WindowResult
from app.core.config import Settings
from app.core.events import Event, EventBus
from app.detect.registry import DeviceRegistry, DeviceView
from app.graph.store import GraphStore, PathStep, RelatedThreat
from app.models.device import Detection
from app.models.risk import RiskDecisionRow
from app.risk.config import Level, RiskConfig
from app.risk.ml import MlExplanation, XgbModel
from app.risk.scorer import Contribution, score

log = logging.getLogger(__name__)

# Per-device memory of destinations already checked against threat intel.
SEEN_DESTINATIONS_MAX = 4096

ACTOR_LABELS = {"IntrusionSet", "Campaign"}
THREAT_LABELS = {"Malware", "Tool", "IntrusionSet", "Campaign"}


class Evidence(BaseModel):
    kind: Literal["trust", "detection", "window", "cve", "kev", "ioc", "actor"]
    summary: str
    value: float
    detail: dict[str, Any] = {}
    path: list[PathStep] | None = None


class Factor(BaseModel):
    name: str
    value: float
    summary: str
    evidence: list[Evidence]


class RiskDecision(BaseModel):
    node_id: str
    ts: datetime
    score: float
    level: Level
    action: str
    contributions: list[Contribution]
    factors: list[Factor]
    explanation: str
    evidence_paths: list[list[PathStep]]
    ml: MlExplanation | None
    trigger: str


def _max(evidence: list[Evidence]) -> float:
    return max((e.value for e in evidence), default=0.0)


class RiskEngine:
    def __init__(
        self,
        settings: Settings,
        cfg: RiskConfig,
        registry: DeviceRegistry,
        pipeline: BehaviorPipeline,
        graph: GraphStore,
        sessions: sessionmaker[Session],
        bus: EventBus,
        ml: XgbModel | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.settings = settings
        self.cfg = cfg
        self.registry = registry
        self.pipeline = pipeline
        self.graph = graph
        self.sessions = sessions
        self.bus = bus
        self.ml = ml
        self.clock = clock
        self._lock = threading.RLock()
        self._last: dict[str, tuple[float, Level, bool]] = {}
        self._seen_destinations: dict[str, set[str]] = {}

    # --- event-driven assessment ----------------------------------------------------

    def on_windows(self, results: list[WindowResult]) -> None:
        """IOC contact check on closed traffic windows.

        A device contacting a known indicator may show no anomaly at all (one
        quiet beacon), so waiting for ANOMALY_DETECTED or the periodic re-score
        would delay the decision by up to 15 minutes. Only destinations not seen
        before for that device are looked up, so steady traffic costs nothing.
        Indicators added *later* for an old destination are picked up by the
        periodic re-score.
        """
        hits: dict[str, tuple[datetime, list[dict[str, Any]]]] = {}
        for r in results:
            seen = self._seen_destinations.setdefault(r.node_id, set())
            fresh = [d for d in r.destinations if d not in seen]
            if len(seen) + len(fresh) > SEEN_DESTINATIONS_MAX:
                seen.clear()  # bounded memory; worst case is a repeat lookup
            seen.update(fresh)
            for dest in fresh:
                if _is_lab_internal(dest, self.settings):
                    continue
                indicators = self.graph.indicators_for(dest)
                if indicators:
                    _, found = hits.setdefault(r.node_id, (r.window_end, []))
                    found.append(
                        {
                            "destination": dest,
                            "indicators": [i["id"] for i in indicators][:5],
                            "sources": sorted(
                                {s for i in indicators for s in i.get("sources") or []}
                            ),
                        }
                    )
        for node_id, (ts, found) in hits.items():
            log.info("new IOC contact", extra={"node_id": node_id, "contacts": found})
            # assess() emits THREAT_CORRELATED (and RISK_UPDATED) itself.
            self.assess(node_id, trigger="IOC_CONTACT", now=ts)

    def on_event(self, event: Event) -> None:
        if event.type in {"DEVICE_CONNECTED", "DEVICE_PROFILED", "ANOMALY_DETECTED"} and (
            event.node_id and event.node_id.startswith("dev-")
        ):
            self.assess(event.node_id, trigger=event.type, now=event.ts)

    # --- factors ---------------------------------------------------------------------

    def _recent_detections(self, node_id: str, now: datetime) -> list[Detection]:
        since = now - timedelta(minutes=self.cfg.factors.lookback_minutes)
        with self.sessions() as session:
            return list(
                session.scalars(
                    select(Detection)
                    .where(
                        Detection.node_id == node_id,
                        Detection.ts >= since,
                        Detection.ts <= now + timedelta(minutes=1),
                    )
                    .order_by(Detection.ts.desc())
                    .limit(200)
                )
            )

    def _unknown_device(self, device: DeviceView) -> Factor:
        value = self.cfg.factors.trust_values[device.trust]
        extra = " with a randomized MAC" if device.randomized_mac else ""
        summary = f"device trust is {device.trust}{extra}"
        return Factor(
            name="unknown_device",
            value=value,
            summary=summary,
            evidence=[
                Evidence(
                    kind="trust",
                    summary=summary,
                    value=value,
                    detail={
                        "trust": device.trust,
                        "first_seen": device.first_seen.isoformat(),
                        "randomized_mac": device.randomized_mac,
                    },
                )
            ],
        )

    def _rate_anomaly(self, detections: list[Detection]) -> Factor:
        evidence: list[Evidence] = []
        for d in detections:
            if d.kind == "anomaly":
                evidence.append(
                    Evidence(
                        kind="detection",
                        summary=d.summary,
                        value=min(1.0, d.score),
                        detail={"detection_id": d.id, "ts": d.ts.isoformat()},
                    )
                )
            elif d.rule_id in self.cfg.factors.rate_rules:
                evidence.append(
                    Evidence(
                        kind="detection",
                        summary=d.summary,
                        value=SEVERITY_SCORE[d.severity],
                        detail={
                            "detection_id": d.id,
                            "rule_id": d.rule_id,
                            "techniques": d.techniques,
                            "ts": d.ts.isoformat(),
                        },
                    )
                )
        evidence = sorted(evidence, key=lambda e: -e.value)[:5]
        value = _max(evidence)
        summary = evidence[0].summary if evidence else "no rate anomalies in the lookback window"
        return Factor(name="rate_anomaly", value=value, summary=summary, evidence=evidence)

    def _protocol_anomaly(self, node_id: str, detections: list[Detection]) -> Factor:
        evidence = [
            Evidence(
                kind="detection",
                summary=d.summary,
                value=SEVERITY_SCORE[d.severity],
                detail={
                    "detection_id": d.id,
                    "rule_id": d.rule_id,
                    "techniques": d.techniques,
                    "ts": d.ts.isoformat(),
                },
            )
            for d in detections
            if d.rule_id in self.cfg.factors.protocol_rules
        ]
        latest = self.pipeline.latest.get(node_id)
        if latest and latest.features.get("new_protocols", 0) > 0:
            evidence.append(
                Evidence(
                    kind="window",
                    value=self.cfg.factors.new_protocol_value,
                    summary=f"{int(latest.features['new_protocols'])} never-seen protocol(s) "
                    f"in the latest window",
                    detail={"window_end": latest.window_end.isoformat()},
                )
            )
        evidence = sorted(evidence, key=lambda e: -e.value)[:5]
        summary = evidence[0].summary if evidence else "protocol mix matches baseline"
        return Factor(
            name="protocol_anomaly", value=_max(evidence), summary=summary, evidence=evidence
        )

    def _cve_matches(self, device: DeviceView) -> list[tuple[dict[str, Any], Any]]:
        out = []
        for guess in device.cpes:
            try:
                matches = self.graph.cves_for_cpe(guess["cpe"])
            except ValueError:
                continue
            out += [(guess, m) for m in matches]
        return out

    def _device_path(self, device: DeviceView, guess: dict[str, Any], m: Any) -> list[PathStep]:
        return [
            PathStep(
                node_id=device.node_id, label="Device", name=device.hostname or device.ip, via=None
            ),
            PathStep(node_id=guess["cpe"], label="CPE", name=guess["cpe"], via="RUNS"),
            PathStep(
                node_id=m.vulnerability_id, label="Vulnerability", name=m.cve, via="AFFECTED_BY"
            ),
        ]

    def _vulnerable_service(
        self, device: DeviceView, matches: list[tuple[dict[str, Any], Any]]
    ) -> Factor:
        mq = self.cfg.factors.match_quality
        evidence = []
        for guess, m in matches:
            value = (m.cvss_score or 5.0) / 10 * guess["confidence"] * mq[m.match]
            evidence.append(
                Evidence(
                    kind="cve",
                    value=round(min(1.0, value), 4),
                    summary=f"{m.cve} (CVSS {m.cvss_score}) affects {guess['cpe'].split(':')[4]} "
                    f"[{m.match} match, CPE confidence {guess['confidence']}]",
                    detail={
                        "cve": m.cve,
                        "cvss": m.cvss_score,
                        "match": m.match,
                        "kev": m.kev,
                        "cpe": guess["cpe"],
                        "cpe_confidence": guess["confidence"],
                    },
                    path=self._device_path(device, guess, m),
                )
            )
        evidence = sorted(evidence, key=lambda e: -e.value)[:5]
        summary = evidence[0].summary if evidence else "no known CVEs for detected services"
        return Factor(
            name="vulnerable_service", value=_max(evidence), summary=summary, evidence=evidence
        )

    def _lookback_start(self, now: datetime) -> datetime:
        return now - timedelta(minutes=self.cfg.factors.lookback_minutes)

    def _recent_destinations(self, node_id: str, now: datetime) -> list[str]:
        found: set[str] = set()
        for window in self.pipeline.recent_windows(node_id, self._lookback_start(now)):
            found.update(window.destinations)
        return sorted(found)

    def _threat_intel(
        self,
        node_id: str,
        device: DeviceView,
        matches: list[tuple[dict[str, Any], Any]],
        now: datetime | None = None,
    ) -> Factor:
        params = self.cfg.factors
        now = now or self.clock()
        evidence: list[Evidence] = []
        sources: set[str] = set()
        # (a) KEV: the device runs something that is actively exploited in the wild.
        for guess, m in matches:
            if not m.kev:
                continue
            value = guess["confidence"] * params.match_quality[m.match]
            ransom = ", used in ransomware" if m.kev_ransomware else ""
            evidence.append(
                Evidence(
                    kind="kev",
                    value=round(value, 4),
                    summary=f"{m.cve} is on CISA KEV (actively exploited{ransom})",
                    detail={"cve": m.cve, "due_date": m.kev_due_date, "cpe": guess["cpe"]},
                    path=self._device_path(device, guess, m),
                )
            )
            sources.add("cisa_kev")
            # (c) actor/campaign links to that CVE (e.g. via dark-web reports).
            vuln_actors = self.graph.related_from_node(m.vulnerability_id, params.max_hops)
            evidence += self._actor_evidence(vuln_actors, sources)
        # (b) IOC contact: destinations this device talked to within the lookback.
        for dest in self._recent_destinations(node_id, now)[:64]:
            if _is_lab_internal(dest, self.settings):
                continue
            for ind in self.graph.indicators_for(dest):
                conf = (ind.get("confidence") or 0) / 100
                sources |= set(ind.get("sources") or [])
                threats = [
                    t
                    for t in self.graph.related_threats(dest, params.max_hops)
                    if t.label in THREAT_LABELS
                ]
                names = ", ".join(sorted({t.name or "?" for t in threats})[:3])
                evidence.append(
                    Evidence(
                        kind="ioc",
                        value=round(conf * (0.5 if ind.get("stale") else 1.0), 4),
                        summary=f"contacted {dest}, a known indicator"
                        + (f" linked to {names}" if names else "")
                        + (" (stale)" if ind.get("stale") else ""),
                        detail={
                            "destination": dest,
                            "indicator": ind["id"],
                            "sources": ind.get("sources"),
                        },
                        path=threats[0].path if threats else None,
                    )
                )
                evidence += self._actor_evidence(threats, sources)
        evidence = sorted(evidence, key=lambda e: -e.value)[:6]
        value = _max(evidence)
        best_conf = max((e.value for e in evidence), default=0.0)
        if evidence and len(sources) <= 1 and best_conf < params.single_source_min_confidence:
            value = min(value, params.single_source_cap)
        summary = evidence[0].summary if evidence else "no threat-intel correlation"
        return Factor(
            name="threat_intel", value=round(value, 4), summary=summary, evidence=evidence
        )

    @staticmethod
    def _actor_evidence(threats: list[RelatedThreat], sources: set[str]) -> list[Evidence]:
        out = []
        for t in threats:
            if t.label in ACTOR_LABELS:
                sources |= set(t.sources)
                out.append(
                    Evidence(
                        kind="actor",
                        value=t.confidence,
                        summary=f"linked to {t.label} {t.name} ({t.hops} hops)",
                        detail={"threat_id": t.threat_id, "sources": t.sources},
                        path=t.path,
                    )
                )
        return out

    # --- decision --------------------------------------------------------------------

    def assess(
        self, node_id: str, trigger: str = "manual", now: datetime | None = None
    ) -> RiskDecision | None:
        with self._lock:
            device = self.registry.get(node_id)
            if device is None:
                return None
            now = now or self.clock()
            detections = self._recent_detections(node_id, now)
            matches = self._cve_matches(device)
            factors = [
                self._unknown_device(device),
                self._rate_anomaly(detections),
                self._protocol_anomaly(node_id, detections),
                self._threat_intel(node_id, device, matches, now),
                self._vulnerable_service(device, matches),
            ]
            linear = score({f.name: f.value for f in factors}, self.cfg)
            action = self.cfg.actions[linear.level]
            protected = _is_protected(device, self.settings)
            if protected and action == "quarantine":
                action = "alert"
            decision = RiskDecision(
                node_id=node_id,
                ts=now,
                score=linear.score,
                level=linear.level,
                action=action,
                contributions=linear.contributions,
                factors=factors,
                explanation=self._explain(
                    linear.score, linear.level, linear.contributions, factors, action, protected
                ),
                evidence_paths=_unique_paths(factors)[:10],
                ml=self._ml(node_id, now),
                trigger=trigger,
            )
            self._persist(decision)
            self._emit(decision)
            return decision

    def _ml(self, node_id: str, now: datetime) -> MlExplanation | None:
        """Explain the most anomalous window in the lookback (not merely the latest)."""
        windows = self.pipeline.recent_windows(node_id, self._lookback_start(now))
        if self.ml is None or not windows:
            return None
        worst = max(windows, key=lambda w: (bool(w.rule_hits), w.anomaly.combined))
        try:
            return self.ml.explain(worst.features)
        except Exception:
            log.exception("ML explanation failed")
            return None

    @staticmethod
    def _explain(
        total: float,
        level: Level,
        contributions: list[Contribution],
        factors: list[Factor],
        action: str,
        protected: bool,
    ) -> str:
        by_name = {f.name: f for f in factors}
        parts = [
            f"{by_name[c.factor].summary} (+{c.contribution:g})"
            for c in sorted(contributions, key=lambda c: -c.contribution)
            if c.contribution > 0
        ]
        head = f"{level.upper()} risk ({total:g}/100)"
        body = "; ".join(parts) if parts else "no risk factors present"
        tail = f". Recommended action: {action}"
        if protected:
            tail += " (protected host: never quarantined)"
        return f"{head}: {body}{tail}."

    def _persist(self, d: RiskDecision) -> None:
        with self.sessions.begin() as session:
            session.add(
                RiskDecisionRow(
                    node_id=d.node_id,
                    ts=d.ts,
                    score=d.score,
                    level=d.level,
                    action=d.action,
                    contributions=[c.model_dump() for c in d.contributions],
                    factors=[f.model_dump(mode="json") for f in d.factors],
                    explanation=d.explanation,
                    evidence_paths=[[s.model_dump() for s in p] for p in d.evidence_paths],
                    ml=d.ml.model_dump() if d.ml else None,
                    trigger=d.trigger,
                )
            )

    def _emit(self, d: RiskDecision) -> None:
        intel = next(f for f in d.factors if f.name == "threat_intel")
        previous = self._last.get(d.node_id)
        correlated = intel.value > 0
        if correlated and (previous is None or not previous[2]):
            self.bus.emit(
                "THREAT_CORRELATED",
                d.node_id,
                ts=d.ts,
                summary=intel.summary,
                value=intel.value,
                evidence=[e.model_dump(mode="json") for e in intel.evidence[:3]],
            )
        if previous is None or previous[:2] != (d.score, d.level):
            self.bus.emit(
                "RISK_UPDATED",
                d.node_id,
                ts=d.ts,
                score=d.score,
                level=d.level,
                action=d.action,
                explanation=d.explanation,
                previous_score=previous[0] if previous else None,
                contributions=[c.model_dump() for c in d.contributions],
            )
        self._last[d.node_id] = (d.score, d.level, correlated)

    # --- reads -----------------------------------------------------------------------

    def history(self, node_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.sessions() as session:
            rows = session.scalars(
                select(RiskDecisionRow)
                .where(RiskDecisionRow.node_id == node_id)
                .order_by(RiskDecisionRow.ts.desc(), RiskDecisionRow.id.desc())
                .limit(limit)
            )
            return [r.as_dict() for r in rows]

    def latest_all(self) -> list[dict[str, Any]]:
        out = []
        for device in self.registry.list():
            hist = self.history(device.node_id, 1)
            if hist:
                out.append(hist[0])
        return sorted(out, key=lambda d: -d["score"])


def _unique_paths(factors: list[Factor]) -> list[list[PathStep]]:
    seen: set[tuple[str, ...]] = set()
    out: list[list[PathStep]] = []
    for f in factors:
        for e in f.evidence:
            if e.path:
                key = tuple(s.node_id for s in e.path)
                if key not in seen:
                    seen.add(key)
                    out.append(e.path)
    return out


def _is_protected(device: DeviceView, settings: Settings) -> bool:
    if not device.ip:
        return False
    try:
        return settings.is_protected(ipaddress.ip_address(device.ip))
    except ValueError:
        return False


def _is_lab_internal(dest: str, settings: Settings) -> bool:
    try:
        return ipaddress.ip_address(dest) in settings.lab_cidr
    except ValueError:
        return False  # a hostname
