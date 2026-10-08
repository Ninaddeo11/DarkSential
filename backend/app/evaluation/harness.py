"""Seeded evaluation of the five Phase 7 scenarios through the real runtime.

Scenarios (each on its own fresh runtime, per seed):

1. ``normal``               the approved fleet, normal traffic only
2. ``unknown_device``        an unapproved device with a randomized MAC joins
3. ``mqtt_flood``            one device floods MQTT CONNECTs at 500/min for 2 min
4. ``kev_ioc``               a device runs GoAhead 3.6.4 (CISA KEV) and beacons to a
                             Feodo C2 IP; other devices contact non-indicator IPs
5. ``quarantine_recovery``   flood + C2 contact; quarantine, then auto-recovery
6. ``kev_only``              a device runs GoAhead 3.6.4 and is NOT attacked: exposed,
                             not compromised (should alert, must not be quarantined)

Ground truth per device: ``benign`` (should not alert), ``unknown`` (should be
flagged as unknown and not quarantined; by design an unknown device alone is
LOW risk), ``vulnerable`` (should alert, must not be quarantined: a patching
problem, not a compromise), ``malicious`` (should alert; quarantine-worthy when
independent signals corroborate).

Two clocks, never mixed:
* **domain time** (event timestamps): detection, correlation and recovery
  latencies, e.g. attack start -> first alert. Bounded below by the 60 s window.
* **wall-clock** (``time.perf_counter``): compute costs on this machine (risk
  assessment, the in-process quarantine path with the dry-run driver).
"""

from __future__ import annotations

import ipaddress
import random
import statistics
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr

from app.behavior.events import TrafficEvent
from app.core.config import BACKEND_ROOT, REPO_ROOT, Settings
from app.core.events import Event
from app.detect.observations import Observation, Service
from app.feeds.config import load_feeds_config
from app.simulation.traffic import Labelled, SimDevice, TrafficSimulator, merge

Truth = Literal["benign", "unknown", "vulnerable", "malicious"]
SCENARIOS = (
    "normal",
    "unknown_device",
    "mqtt_flood",
    "kev_ioc",
    "quarantine_recovery",
    "kev_only",
)
SINGLE_SIGNAL = ("mqtt_flood",)  # one behavioral signal, nothing corroborating
MULTI_SIGNAL = ("kev_ioc", "quarantine_recovery")  # independent signals agree
START = datetime(2026, 3, 1, 8, tzinfo=UTC)
WARMUP_MIN = 35  # baselines mature before anything happens
ATTACK_MIN = 40
DURATION_MIN = 60
ROGUE = SimDevice("rogue-sensor", "02:5e:aa:bb:cc:99", "192.168.50.99", "esp32_sensor")
EVAL_KEY = "phase7-evaluation-key-not-a-secret-0123456789"  # fixed: reproducible node ids


@dataclass
class DeviceRow:
    scenario: str
    seed: int
    device: str
    truth: Truth
    max_score: float
    max_level: str
    final_score: float
    final_level: str
    alerted: bool  # reached medium or above at any point
    quarantine_worthy: bool  # the engine recommended (automatic) quarantine at any point
    quarantined: bool
    flagged_unknown: bool  # unknown_device factor at full value in the final decision
    attack_start_s: float | None = None  # seconds from scenario start
    first_detection_s: float | None = None  # latency after attack start (domain)
    first_alert_s: float | None = None  # latency to RISK_UPDATED >= medium (domain)
    correlation_s: float | None = None  # latency to an IOC-backed assessment (domain)


@dataclass
class ContactRow:
    seed: int
    device: str
    destination: str
    is_indicator: bool
    correlated: bool


@dataclass
class TimingRow:
    scenario: str
    seed: int
    metric: Literal["risk_assess_ms", "quarantine_ms", "recovery_s", "discovery_s"]
    value: float


@dataclass
class WindowRow:
    scenario: str
    seed: int
    device: str
    window_end: str
    attack: bool
    flagged: bool


@dataclass
class Results:
    devices: list[DeviceRow] = field(default_factory=list)
    contacts: list[ContactRow] = field(default_factory=list)
    timings: list[TimingRow] = field(default_factory=list)
    windows: list[WindowRow] = field(default_factory=list)
    thresholds: dict[str, float] = field(default_factory=dict)

    def extend(self, other: Results) -> None:
        self.devices += other.devices
        self.contacts += other.contacts
        self.timings += other.timings
        self.windows += other.windows
        self.thresholds = other.thresholds or self.thresholds


def feodo_ips() -> list[str]:
    import json

    data = json.loads((REPO_ROOT / "fixtures" / "feodo" / "ipblocklist.sample.json").read_text())
    return sorted(str(row["ip_address"]) for row in data)


def eval_settings(models_dir: Path, risk_config: Path | None = None) -> Settings:
    return Settings(
        device_id_hmac_key=SecretStr(EVAL_KEY),
        env="test",
        offline_mode=True,
        dry_run=True,
        database_url="sqlite://",
        scheduler_enabled=False,
        iforest_autotrain=True,
        xgb_autotrain=False,
        models_dir=models_dir,
        protected_hosts=[ipaddress.ip_address("192.168.50.1")],
        quarantine_minutes=10,
        fixtures_dir=REPO_ROOT / "fixtures",
        risk_config_path=risk_config or BACKEND_ROOT / "config" / "risk.yaml",
        log_json=False,
        log_level="WARNING",
        # Isolated from any local .env: in-memory graph, no broker, no capture.
        neo4j_uri=None,
        mqtt_host=None,
        mqtt_broker_log=None,
        nmap_enabled=False,
        passive_capture_enabled=False,
        ble_scan_enabled=False,
        wifi_monitor_enabled=False,
    )


@contextmanager
def runtime(models_dir: Path, risk_config: Path | None = None) -> Iterator[Any]:
    from app.runtime import LabRuntime

    settings = eval_settings(models_dir, risk_config)
    rt = LabRuntime.build(settings, load_feeds_config(settings.feeds_config_path))
    try:
        for feed in ("mitre_attack", "cisa_kev", "nvd_cve", "feodo"):
            rt.runner.run(feed)
        yield rt
    finally:
        rt.stop()


class Recorder:
    """Bus subscriber keeping each event with its wall-clock arrival time."""

    def __init__(self) -> None:
        self.events: list[tuple[Event, float]] = []

    def __call__(self, event: Event) -> None:
        self.events.append((event, time.perf_counter()))

    def of(self, node: str, *types: str) -> list[tuple[Event, float]]:
        return [(e, t) for e, t in self.events if e.node_id == node and e.type in types]


def _approve_fleet(rt: Any, sim: TrafficSimulator) -> dict[str, str]:
    """The known fleet is approved before the scenario (the rogue is not)."""
    nodes = {}
    for dev in sim.fleet:
        view = rt.registry.observe(Observation(source="arp", ts=START, mac=dev.mac, ip=dev.ip))
        rt.registry.approve(view.node_id)
        nodes[dev.name] = view.node_id
    return nodes


def _contacts(
    dev: SimDevice, at: datetime, dest: str, n: int, rng: random.Random
) -> list[Labelled]:
    return [
        Labelled(
            TrafficEvent(
                ts=at + timedelta(seconds=i * 7 + rng.uniform(0, 2)),
                src_mac=dev.mac,
                src_ip=dev.ip,
                dst_ip=dest,
                dst_port=8080,
                proto="tcp",
            ),
            "c2_contact",
            dev.name,
        )
        for i in range(n)
    ]


def _level_rank(level: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(level, -1)


def run_scenario(
    name: str, seed: int, models_dir: Path, risk_config: Path | None = None
) -> Results:
    rng = random.Random(f"{name}:{seed}")
    sim = TrafficSimulator(seed=seed)
    attack_at = START + timedelta(minutes=ATTACK_MIN, seconds=rng.randint(0, 50))
    streams = [sim.normal(START, DURATION_MIN)]
    truth: dict[str, Truth] = {d.name: "benign" for d in sim.fleet}
    attack_dev: SimDevice | None = None
    contacts: list[tuple[str, str, bool]] = []
    out = Results()

    if name == "unknown_device":
        rogue = TrafficSimulator(seed=seed + 10_000, fleet=(ROGUE,))
        streams.append([le for le in rogue.normal(START, DURATION_MIN) if le.event.ts >= attack_at])
        truth[ROGUE.name] = "unknown"
    elif name == "mqtt_flood":
        attack_dev = sim.device("plug-desk")
        streams.append(sim.mqtt_flood(attack_dev, attack_at, minutes=2, per_minute=500))
    elif name in ("kev_ioc", "quarantine_recovery"):
        attack_dev = sim.device("cam-front" if name == "kev_ioc" else "esp32-node")
        ioc = rng.choice(feodo_ips())
        streams.append(_contacts(attack_dev, attack_at, ioc, 3, rng))
        contacts.append((attack_dev.name, ioc, True))
        if name == "kev_ioc":
            for dev in sim.fleet:  # decoys: every other device contacts a non-indicator IP
                if dev is attack_dev:
                    continue
                decoy = f"198.51.100.{rng.randint(2, 250)}"  # TEST-NET-2, never in feeds
                streams.append(_contacts(dev, attack_at, decoy, 3, rng))
                contacts.append((dev.name, decoy, False))
        else:
            streams.append(sim.mqtt_flood(attack_dev, attack_at, minutes=2, per_minute=500))
    kev_dev: SimDevice | None = None
    if name == "kev_only":
        kev_dev = sim.device("cam-front")
        truth[kev_dev.name] = "vulnerable"
    elif name == "kev_ioc":
        kev_dev = attack_dev
    if attack_dev is not None:
        truth[attack_dev.name] = "malicious"

    events = merge(*streams)
    with runtime(models_dir, risk_config) as rt:
        nodes = _approve_fleet(rt, sim)
        # Wall-clock cost of each quarantine the response service performs (the bus
        # hands RISK_UPDATED to the response service before any later subscriber,
        # so timing between two bus events would be meaningless here).
        quarantine_ms: list[float] = []
        original_quarantine = rt.response.quarantine

        def timed_quarantine(*args: Any, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            try:
                return original_quarantine(*args, **kwargs)
            finally:
                quarantine_ms.append((time.perf_counter() - t0) * 1000)

        rt.response.quarantine = timed_quarantine
        rec = Recorder()  # after approval: pre-approval assessments aren't scenario data
        rt.bus.subscribe(rec)
        if kev_dev is not None:
            rt.registry.observe(
                Observation(
                    source="nmap",
                    ts=START,
                    mac=kev_dev.mac,
                    ip=kev_dev.ip,
                    services=[
                        Service(port=80, name="http", product="GoAhead WebServer", version="3.6.4")
                    ],
                )
            )
        rt.pipeline.ingest([le.event for le in events])
        rt.pipeline.flush()
        end = START + timedelta(minutes=DURATION_MIN + 1)
        if ROGUE.name in truth:
            nodes[ROGUE.name] = rt.registry.resolve(mac=ROGUE.mac, ip=ROGUE.ip)

        # Quarantine -> auto-recovery (scenario 5).
        if name == "quarantine_recovery" and attack_dev is not None:
            node = nodes[attack_dev.name]
            auto = [e for e, _ in rec.of(node, "QUARANTINE_COMPLETED") if e.payload.get("ok")]
            if auto:  # the risk engine quarantined it automatically
                qid = auto[0].payload["quarantine_id"]
            else:  # below the critical threshold: the operator quarantines manually
                q = rt.response.quarantine(
                    node, "evaluation: operator action", actor="eval:operator", now=end
                )
                qid = q["id"]
            out.timings += [TimingRow(name, seed, "quarantine_ms", v) for v in quarantine_ms[:1]]
            q = rt.response.get(qid)
            expires = datetime.fromisoformat(str(q["expires_at"]))
            # Sweep-only path (the persistent per-quarantine job is disabled here): the
            # 60 s sweep runs at a random phase relative to the quarantine.
            tick = datetime.fromisoformat(str(q["started_at"])) + timedelta(
                seconds=rng.uniform(0, 60)
            )
            while rt.response.get(qid)["status"] == "active" and tick < expires + timedelta(
                hours=1
            ):
                tick += timedelta(seconds=60)  # the 60 s response sweep
                rt.response.expire_due(tick)
            released = rt.response.get(qid)
            if released["status"] == "released":
                out.timings.append(
                    TimingRow(
                        name,
                        seed,
                        "recovery_s",
                        (
                            datetime.fromisoformat(str(released["released_at"])) - expires
                        ).total_seconds(),
                    )
                )

        # Final assessment of every device (wall-clock timed) + the device rows.
        for dev_name, node in nodes.items():
            if node is None:
                continue
            t0 = time.perf_counter()
            final = rt.risk.assess(node, trigger="evaluation", now=end)
            out.timings.append(
                TimingRow(name, seed, "risk_assess_ms", (time.perf_counter() - t0) * 1000)
            )
            if final is None:
                continue
            updates = [e for e, _ in rec.of(node, "RISK_UPDATED")]
            scores = [(float(e.payload["score"]), str(e.payload["level"])) for e in updates]
            scores.append((final.score, final.level))
            max_score, max_level = max(scores, key=lambda s: s[0])
            row = DeviceRow(
                scenario=name,
                seed=seed,
                device=dev_name,
                truth=truth[dev_name],
                max_score=max_score,
                max_level=max_level,
                final_score=final.score,
                final_level=final.level,
                alerted=any(_level_rank(lv) >= 1 for _, lv in scores),
                quarantine_worthy=final.action == "quarantine"
                or any(e.payload.get("action") == "quarantine" for e in updates),
                quarantined=bool(rec.of(node, "QUARANTINE_COMPLETED")),
                flagged_unknown=any(
                    c.factor == "unknown_device" and c.value >= 1.0 for c in final.contributions
                ),
            )
            history = rt.risk.history(node, limit=1000)
            if truth[dev_name] in ("unknown", "malicious"):
                row.attack_start_s = (attack_at - START).total_seconds()
                after = [
                    e.ts
                    for e, _ in rec.of(node, "ANOMALY_DETECTED", "THREAT_CORRELATED")
                    if e.ts >= attack_at
                ]
                alerts = [
                    e.ts
                    for e in updates
                    if e.ts >= attack_at and _level_rank(str(e.payload["level"])) >= 1
                ]
                ioc_ts = [
                    datetime.fromisoformat(str(h["ts"]))
                    for h in history
                    if h.get("trigger") == "IOC_CONTACT"
                    and datetime.fromisoformat(str(h["ts"])) >= attack_at
                ]
                after += ioc_ts
                if after:
                    row.first_detection_s = (min(after) - attack_at).total_seconds()
                if alerts:
                    row.first_alert_s = (min(alerts) - attack_at).total_seconds()
                if ioc_ts:
                    row.correlation_s = (min(ioc_ts) - attack_at).total_seconds()
            out.devices.append(row)

            if dev_name == ROGUE.name:
                connected = rec.of(node, "DEVICE_CONNECTED")
                first_packet = min(le.event.ts for le in events if le.device == ROGUE.name)
                if connected:
                    out.timings.append(
                        TimingRow(
                            name,
                            seed,
                            "discovery_s",
                            (connected[0][0].ts - first_packet).total_seconds(),
                        )
                    )

            # Correlation accuracy: is each contact backed by IOC evidence (or not)?
            for dev_c, dest, is_ioc in contacts:
                if dev_c != dev_name:
                    continue
                # Any assessment in the run (a contact ages out of the lookback later).
                hit = any(
                    ev.get("kind") == "ioc" and (ev.get("detail") or {}).get("destination") == dest
                    for h in history
                    for f in h.get("factors", [])
                    if f.get("name") == "threat_intel"
                    for ev in f.get("evidence", [])
                )
                out.contacts.append(ContactRow(seed, dev_name, dest, is_ioc, hit))

            # Window-level detection vs ground truth.
            attack_windows = {
                _floor(le.event.ts)
                for le in events
                if le.device == dev_name and le.label != "normal"
            }
            flagged = {
                str(e.payload.get("window_end"))
                for e, _ in rec.of(node, "ANOMALY_DETECTED")
                if e.payload.get("window_end")
            }
            for w in rt.pipeline.history.get(node, []):
                if w.window_end <= START + timedelta(minutes=WARMUP_MIN):
                    continue
                end_iso = w.window_end.isoformat()
                out.windows.append(
                    WindowRow(
                        name,
                        seed,
                        dev_name,
                        end_iso,
                        attack=w.window_start in attack_windows,
                        flagged=end_iso in flagged or bool(w.anomaly.is_anomaly or w.rule_hits),
                    )
                )
        out.thresholds = dict(rt.risk.cfg.thresholds)
    return out


def _floor(ts: datetime, seconds: int = 60) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, UTC)


def run_all(
    seeds: list[int],
    scenarios: tuple[str, ...] = SCENARIOS,
    progress: Callable[[str], None] | None = None,
    thresholds: dict[str, float] | None = None,
) -> Results:
    """Run every scenario for every seed. ``thresholds`` overrides the risk
    levels (the rest of config/risk.yaml is used unchanged)."""
    import yaml

    results = Results()
    with tempfile.TemporaryDirectory(prefix="dsn-eval-") as tmp:
        models = Path(tmp) / "models"  # the Isolation Forest is trained once, then loaded
        risk_config = None
        if thresholds is not None:
            cfg = yaml.safe_load((BACKEND_ROOT / "config" / "risk.yaml").read_text("utf-8"))
            cfg["thresholds"] = thresholds
            risk_config = Path(tmp) / "risk.yaml"
            risk_config.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        for seed in seeds:
            for name in scenarios:
                if progress:
                    progress(f"{name} seed={seed}")
                results.extend(run_scenario(name, seed, models, risk_config))
    return results


# --- metrics --------------------------------------------------------------------------


def rate(num: int, den: int) -> float | None:
    return num / den if den else None


def summarize(r: Results) -> dict[str, Any]:
    by_truth: dict[str, list[DeviceRow]] = {
        "benign": [], "unknown": [], "vulnerable": [], "malicious": [],
    }  # fmt: skip
    for d in r.devices:
        by_truth[d.truth].append(d)
    should_alert = by_truth["malicious"]
    multi = [d for d in by_truth["malicious"] if d.scenario in MULTI_SIGNAL]
    single = [d for d in by_truth["malicious"] if d.scenario in SINGLE_SIGNAL]
    not_malicious = by_truth["benign"] + by_truth["unknown"] + by_truth["vulnerable"]
    tp_c = sum(c.correlated for c in r.contacts if c.is_indicator)
    fn_c = sum(not c.correlated for c in r.contacts if c.is_indicator)
    fp_c = sum(c.correlated for c in r.contacts if not c.is_indicator)
    tn_c = sum(not c.correlated for c in r.contacts if not c.is_indicator)
    win_pos = [w for w in r.windows if w.attack]
    win_neg = [w for w in r.windows if not w.attack]

    def dist(values: list[float]) -> dict[str, float | int | None]:
        if not values:
            return {"n": 0, "p50": None, "p95": None, "max": None}
        ordered = sorted(values)
        p95 = ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]
        return {"n": len(values), "p50": statistics.median(values), "p95": p95, "max": ordered[-1]}

    def timing(metric: str) -> dict[str, float | int | None]:
        return dist([t.value for t in r.timings if t.metric == metric])

    def latency(scenario: str, attr: str) -> dict[str, float | int | None]:
        vals = [
            getattr(d, attr) for d in r.devices
            if d.scenario == scenario and d.truth != "benign" and getattr(d, attr) is not None
        ]  # fmt: skip
        return dist(vals)

    return {
        "devices": {k: len(v) for k, v in by_truth.items()},
        "alert_tpr": rate(sum(d.alerted for d in should_alert), len(should_alert)),
        "unknown_flagged": rate(
            sum(d.flagged_unknown and not d.quarantined for d in by_truth["unknown"]),
            len(by_truth["unknown"]),
        ),
        "unknown_alerted": rate(
            sum(d.alerted for d in by_truth["unknown"]), len(by_truth["unknown"])
        ),
        "alert_fpr": rate(sum(d.alerted for d in by_truth["benign"]), len(by_truth["benign"])),
        "vulnerable_alerted": rate(
            sum(d.alerted for d in by_truth["vulnerable"]), len(by_truth["vulnerable"])
        ),
        "vulnerable_quarantined": rate(
            sum(d.quarantine_worthy for d in by_truth["vulnerable"]), len(by_truth["vulnerable"])
        ),
        # Policy: corroborated (multi-signal) compromises are quarantine-worthy; a single
        # anomaly alone should alert but not quarantine.
        "quarantine_tpr": rate(sum(d.quarantine_worthy for d in multi), len(multi)),
        "single_signal_quarantined": rate(sum(d.quarantine_worthy for d in single), len(single)),
        "quarantine_fpr": rate(sum(d.quarantine_worthy for d in not_malicious), len(not_malicious)),
        "window_tpr": rate(sum(w.flagged for w in win_pos), len(win_pos)),
        "window_fpr": rate(sum(w.flagged for w in win_neg), len(win_neg)),
        "windows": {"attack": len(win_pos), "normal": len(win_neg)},
        "correlation": {
            "tp": tp_c,
            "fn": fn_c,
            "fp": fp_c,
            "tn": tn_c,
            "accuracy": rate(tp_c + tn_c, tp_c + tn_c + fp_c + fn_c),
            "precision": rate(tp_c, tp_c + fp_c),
            "recall": rate(tp_c, tp_c + fn_c),
        },
        "latency_s": {
            s: {
                "first_detection": latency(s, "first_detection_s"),
                "first_alert": latency(s, "first_alert_s"),
                "correlation": latency(s, "correlation_s"),
            }
            for s in SCENARIOS
            if s != "normal"
        },
        "timing": {
            m: timing(m) for m in ("risk_assess_ms", "quarantine_ms", "recovery_s", "discovery_s")
        },
        "thresholds": r.thresholds,
    }


def calibrate(r: Results) -> dict[str, Any]:
    """Derive risk thresholds from scores, by a fixed rule (no hand tuning).

    Uses each device's highest score in its scenario:

    * **medium (alert)**: midway between the highest score of devices that must
      not alert (benign, unknown) and the lowest score of devices that must
      (vulnerable, any attack).
    * **critical**: midway between the strongest single-signal attack (a flood
      alone: alert, not quarantine) and the weakest corroborated compromise
      (KEV + C2, flood + C2). Exposure-only devices may also score critical; the
      engine's compromise-evidence gate turns that into an operator review
      instead of an automatic quarantine, so they don't constrain this threshold.
    * **high**: midway between the two.

    Run on calibration seeds; evaluate on different (held-out) seeds.
    """
    quiet = [d.max_score for d in r.devices if d.truth in ("benign", "unknown")]
    alerting = [d.max_score for d in r.devices if d.truth in ("vulnerable", "malicious")]
    single = [
        d.max_score for d in r.devices if d.truth == "malicious" and d.scenario in SINGLE_SIGNAL
    ]
    corroborated = [
        d.max_score for d in r.devices if d.truth == "malicious" and d.scenario in MULTI_SIGNAL
    ]
    out: dict[str, Any] = {
        "max_must_not_alert": max(quiet, default=None),
        "min_must_alert": min(alerting, default=None),
        "max_single_signal": max(single, default=None),
        "min_corroborated": min(corroborated, default=None),
        "current": r.thresholds,
    }
    if not (quiet and alerting and single and corroborated):
        out["separable"] = False
        return out
    out["separable"] = max(quiet) < min(alerting) and max(single) < min(corroborated)
    if not out["separable"]:
        return out
    medium = round((max(quiet) + min(alerting)) / 2, 1)
    critical = round((max(single) + min(corroborated)) / 2, 1)
    out["margins"] = {
        "alert": round(min(alerting) - max(quiet), 2),
        "quarantine": round(min(corroborated) - max(single), 2),
    }
    out["suggested"] = {
        "low": 0.0,
        "medium": medium,
        "high": round((medium + critical) / 2, 1),
        "critical": critical,
    }
    return out


def rows(items: list[Any]) -> list[dict[str, Any]]:
    return [asdict(i) for i in items]
