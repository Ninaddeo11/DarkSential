"""Lab runtime: DB, graph, feeds, device registry, behavior pipeline, discovery.

Imported lazily by ``app.main`` only when ``deployment == "lab"``, so hosted
(serverless) deployments never import the heavy `lab` extra.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.behavior.anomaly import AnomalyScorer, IForestModel, ModelIntegrityError
from app.behavior.config import BehaviorConfig, load_behavior_config
from app.behavior.pipeline import BehaviorPipeline, train_model
from app.core.config import Settings
from app.core.db import init_db, make_engine, make_session_factory
from app.core.events import EventBus
from app.core.health import CheckResult
from app.core.identifiers import DeviceIdHasher
from app.detect import capabilities
from app.detect.registry import DeviceRegistry, load_devices_config, node_id_for
from app.detect.rules import RuleEngine
from app.feeds import jobs
from app.feeds.config import FeedsFile
from app.feeds.runner import FeedRunner
from app.feeds.scheduler import FeedScheduler
from app.feeds.status import FeedStatusResponse
from app.graph.memory import InMemoryGraphStore
from app.graph.store import GraphStore
from app.mqtt.commands import NullPublisher, PahoPublisher, Publisher, StatusNodeCommander
from app.mqtt.telemetry import TELEMETRY_TOPIC, TelemetryConsumer
from app.response.audit import AuditLog
from app.response.drivers import DriverError, DryRunDriver, ResponseDriver, build_driver
from app.response.service import ResponseService
from app.risk.config import load_risk_config
from app.risk.engine import RiskEngine
from app.risk.ml import XgbModel

log = logging.getLogger(__name__)

TRUST_REFRESH_SECONDS = 3600
RESPONSE_SWEEP_SECONDS = 60
RISK_RESCORE_SECONDS = 900


def _build_driver(settings: Settings) -> tuple[ResponseDriver, str | None]:
    """Requested driver, or dry-run with an error surfaced in readiness (fail safe)."""
    try:
        return build_driver(settings.response_driver, settings.dry_run), None
    except DriverError as exc:
        log.error(
            "enforcement driver unavailable: falling back to dry-run",
            extra={"driver": settings.response_driver, "error": str(exc)},
        )
        return DryRunDriver(), f"{settings.response_driver} unavailable ({exc}); using dry-run"


def _build_publisher(
    settings: Settings,
    on_ack: Callable[[bytes], None],
    subscriptions: dict[str, Callable[[str, bytes], object]] | None = None,
) -> Publisher:
    if not settings.mqtt_host or not settings.mqtt_username or not settings.mqtt_password:
        return NullPublisher()
    return PahoPublisher(
        settings.mqtt_host,
        settings.mqtt_port,
        settings.mqtt_username,
        settings.mqtt_password.get_secret_value(),
        tls=settings.mqtt_tls,
        ca_file=settings.mqtt_ca_file,
        on_ack=on_ack,
        subscriptions=subscriptions,
    )


def _broker_ip(settings: Settings) -> str | None:
    try:
        return ipaddress.ip_address(settings.mqtt_host or "").compressed
    except ValueError:
        return None


def build_graph_store(settings: Settings) -> GraphStore:
    if settings.neo4j_uri and settings.neo4j_password is not None:
        from app.graph.neo4j_store import Neo4jGraphStore

        return Neo4jGraphStore(
            settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password.get_secret_value()
        )
    log.warning("DSN_NEO4J_URI unset: using the in-memory graph (not persistent)")
    return InMemoryGraphStore()


def load_or_train_model(settings: Settings, cfg: BehaviorConfig) -> IForestModel | None:
    key = settings.device_id_hmac_key.get_secret_value().encode("utf-8")
    try:
        return IForestModel.load(settings.models_dir, key)
    except FileNotFoundError:
        pass
    except ModelIntegrityError as exc:
        log.error("Isolation Forest model rejected; retraining", extra={"error": str(exc)})
    except ImportError as exc:
        log.warning("Isolation Forest unavailable on this host", extra={"error": str(exc)})
        return None
    if not settings.iforest_autotrain:
        return None
    try:
        model = train_model(cfg)
    except ImportError as exc:
        log.warning("Isolation Forest unavailable on this host", extra={"error": str(exc)})
        return None
    model.save(settings.models_dir, key)
    log.info("Isolation Forest trained", extra={"samples": model.meta["n_samples"]})
    return model


def load_or_train_xgb(settings: Settings, cfg: BehaviorConfig) -> XgbModel | None:
    key = settings.device_id_hmac_key.get_secret_value().encode("utf-8")
    directory = settings.models_dir
    try:
        return XgbModel.load(directory, key)
    except FileNotFoundError:
        pass
    except ModelIntegrityError as exc:
        log.error("XGBoost model rejected; retraining", extra={"error": str(exc)})
    except ImportError as exc:
        log.warning("XGBoost unavailable on this host", extra={"error": str(exc)})
        return None
    if not settings.xgb_autotrain:
        return None
    try:
        from app.risk.ml import train_default

        model = train_default(cfg)
    except ImportError as exc:
        log.warning("XGBoost/SHAP unavailable on this host", extra={"error": str(exc)})
        return None
    model.save(directory, key)
    log.info("XGBoost risk comparison model trained", extra={"samples": model.meta["n_samples"]})
    return model


@dataclass
class LabRuntime:
    settings: Settings
    engine: Engine
    sessions: sessionmaker[Session]
    graph: GraphStore
    runner: FeedRunner
    scheduler: FeedScheduler | None
    bus: EventBus
    registry: DeviceRegistry
    rules: RuleEngine
    pipeline: BehaviorPipeline
    behavior_cfg: BehaviorConfig
    risk: RiskEngine
    response: ResponseService
    audit: AuditLog
    publisher: Publisher
    response_error: str | None = None
    telemetry: TelemetryConsumer | None = None
    _services: list[Any] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        settings: Settings,
        feeds: FeedsFile,
        graph: GraphStore | None = None,
        bus: EventBus | None = None,
    ) -> LabRuntime:
        engine = make_engine(settings.database_url)
        init_db(engine)
        sessions = make_session_factory(engine)
        graph = graph or build_graph_store(settings)
        bus = bus or EventBus()
        runner = FeedRunner(settings, feeds, graph, sessions)
        hasher = DeviceIdHasher(settings.device_id_hmac_key.get_secret_value().encode("utf-8"))
        registry = DeviceRegistry(
            sessions, hasher, load_devices_config(settings.devices_config_path), bus
        )
        behavior_cfg = load_behavior_config(settings.behavior_config_path)
        rules = RuleEngine.load(settings.rules_config_path)
        scorer = AnomalyScorer(behavior_cfg.anomaly, load_or_train_model(settings, behavior_cfg))
        pipeline = BehaviorPipeline(registry, behavior_cfg, rules, scorer, bus, sessions)
        risk = RiskEngine(
            settings,
            load_risk_config(settings.risk_config_path),
            registry,
            pipeline,
            graph,
            sessions,
            bus,
            ml=load_or_train_xgb(settings, behavior_cfg),
        )
        bus.subscribe(risk.on_event)
        audit = AuditLog(sessions)
        driver, response_error = _build_driver(settings)
        holder: dict[str, ResponseService] = {}
        telemetry = TelemetryConsumer(
            registry.observe,
            None if settings.mqtt_broker_log else pipeline.ingest,
            broker_ip=_broker_ip(settings),
        )
        publisher = _build_publisher(
            settings,
            lambda raw: holder["svc"].on_ack(raw),
            {TELEMETRY_TOPIC: telemetry.handle},
        )
        key = (
            settings.mqtt_command_key.get_secret_value().encode()
            if settings.mqtt_command_key
            else None
        )
        response = ResponseService(
            settings, driver, sessions, registry, bus, audit, StatusNodeCommander(publisher, key)
        )
        holder["svc"] = response
        bus.subscribe(response.on_event)
        caps = capabilities.report(settings)
        named = {
            "trust_refresh": TRUST_REFRESH_SECONDS,
            "response_sweep": RESPONSE_SWEEP_SECONDS,
            "risk_rescore": RISK_RESCORE_SECONDS,
            "pipeline_tick": behavior_cfg.window_seconds,
        }
        if caps["nmap"].active:
            named["nmap_discovery"] = settings.nmap_interval_minutes * 60
        scheduler = (
            FeedScheduler(engine, feeds, named_jobs=named) if settings.scheduler_enabled else None
        )
        rt = cls(
            settings,
            engine,
            sessions,
            graph,
            runner,
            scheduler,
            bus,
            registry,
            rules,
            pipeline,
            behavior_cfg,
            risk,
            response,
            audit,
            publisher,
            response_error,
        )
        runner.on_success.append(rt._on_feed_success)
        if scheduler is not None:
            sched = scheduler
            response.schedule_recovery = lambda qid, at: sched.schedule_once(
                f"recover:{qid}", "app.feeds.jobs:run_recovery_job", at, [qid]
            )
            response.cancel_recovery = lambda qid: sched.cancel(f"recover:{qid}")
        rt.telemetry = telemetry
        return rt

    @property
    def graph_backend(self) -> str:
        return "memory" if isinstance(self.graph, InMemoryGraphStore) else "neo4j"

    # --- lifecycle -------------------------------------------------------------------

    def start(self) -> None:
        try:
            self.graph.ensure_schema()
            self.link_rules()
        except Exception as exc:
            # Readiness reports it; ingestion retries schema creation on first run.
            log.error("graph schema setup failed", extra={"error": type(exc).__name__})
        jobs.set_runner(self.runner)
        jobs.register("trust_refresh", self.registry.refresh_trust)
        jobs.register("nmap_discovery", self.run_nmap)
        jobs.register("response_sweep", self.response.expire_due)
        jobs.register("risk_rescore", self.rescore_all)
        # Live traffic: close windows on wall-clock time even if a device goes quiet.
        jobs.register("pipeline_tick", lambda: self.pipeline.tick(datetime.now(UTC)))
        jobs.set_recovery(
            lambda qid: self.response.release(
                qid, actor="system:auto-recovery", reason="quarantine expired"
            )
        )
        try:
            diff = self.response.reconcile()
            log.info("firewall reconciled", extra=diff)
        except Exception as exc:
            self.response_error = f"reconcile failed: {type(exc).__name__}"
            log.error("firewall reconciliation failed", extra={"error": str(exc)})
        self._start_discovery()
        if self.scheduler:
            self.scheduler.start()

    def stop(self) -> None:
        for service in self._services:
            try:
                service.stop()
            except Exception:
                log.exception("discovery service failed to stop")
        if self.scheduler:
            self.scheduler.shutdown()
        jobs.set_runner(None)
        jobs.set_recovery(None)
        jobs.clear_named()
        self.publisher.close()
        self.graph.close()
        self.engine.dispose()

    def _start_discovery(self) -> None:
        if self.settings.mqtt_broker_log:
            from app.mqtt.brokerlog import BrokerLogParser, BrokerLogTailer

            tailer = BrokerLogTailer(
                self.settings.mqtt_broker_log,
                BrokerLogParser(
                    _broker_ip(self.settings), frozenset(self.settings.mqtt_service_clients)
                ),
                self.pipeline.ingest,
            )
            tailer.start()
            self._services.append(tailer)
        caps = capabilities.report(self.settings)
        if caps["passive"].active:
            from app.detect.passive import PassiveObserver

            svc: Any = PassiveObserver(self.registry.observe, self.settings.passive_capture_iface)
            svc.start()
            self._services.append(svc)
        if caps["ble"].active:
            from app.detect.ble import BleScanner

            svc = BleScanner(self.registry.observe)
            svc.start()
            self._services.append(svc)
        if caps["wifi"].active and self.settings.wifi_monitor_iface:
            from app.detect.wifi import DeauthAlert, DeauthMonitor

            def on_alert(alert: DeauthAlert) -> None:
                self.pipeline.record_alert(
                    node_id_for(alert.bssid_hmac),
                    "wifi_deauth_flood",
                    {
                        "frames": alert.frames,
                        "rate_per_min": alert.rate_per_min,
                        "kinds": alert.kinds,
                    },
                    datetime.now(UTC),
                )

            hasher = DeviceIdHasher(
                self.settings.device_id_hmac_key.get_secret_value().encode("utf-8")
            )
            svc = DeauthMonitor(hasher, on_alert)
            svc.start(self.settings.wifi_monitor_iface)
            self._services.append(svc)

    def run_nmap(self) -> int:
        from app.detect.nmap_scan import scan

        result = scan(self.settings, "service")
        for obs in result.observations:
            self.registry.observe(obs)
        return len(result.observations)

    def rescore_all(self) -> int:
        """Periodic re-assessment, so quiet devices don't keep a stale score."""
        count = 0
        for device in self.registry.list():
            if self.risk.assess(device.node_id, trigger="periodic"):
                count += 1
        return count

    def link_rules(self) -> dict[str, list[str]]:
        """Map each rule to its ATT&CK techniques in the graph; returns missing IDs."""
        missing = {
            rule.id: self.graph.link_rule(rule.id, rule.techniques, rule.rationale)
            for rule in self.rules.rules
        }
        return {k: v for k, v in missing.items() if v}

    def _on_feed_success(self, feed: str) -> None:
        if feed == "mitre_attack":
            missing = self.link_rules()
            if missing:
                log.warning(
                    "rules reference techniques missing from ATT&CK", extra={"missing": missing}
                )

    # --- views -----------------------------------------------------------------------

    def feed_status(self) -> FeedStatusResponse:
        sched = self.scheduler
        return FeedStatusResponse(
            scheduler=("running" if sched.running else "stopped") if sched else "disabled",
            graph_backend=self.graph_backend,  # type: ignore[arg-type]
            feeds=self.runner.statuses(sched.next_run if sched else lambda _: None),
        )

    # --- health checks ---------------------------------------------------------------

    async def check_database(self) -> CheckResult:
        def probe() -> None:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))

        await asyncio.to_thread(probe)
        return CheckResult(status="ok")

    async def check_response(self) -> CheckResult:
        active = len(self.response.list(status="active"))
        detail = f"driver={self.response.driver.name}, active_quarantines={active}"
        if self.response_error:
            return CheckResult(status="error", detail=f"{self.response_error}; {detail}")
        return CheckResult(status="ok", detail=detail)

    async def check_mqtt(self) -> CheckResult:
        if isinstance(self.publisher, NullPublisher):
            return CheckResult(status="not_configured", detail="DSN_MQTT_HOST unset")
        connected = bool(getattr(self.publisher, "connected", lambda: False)())
        return CheckResult(
            status="ok" if connected else "degraded",
            detail="connected" if connected else "connecting",
        )

    async def check_graph(self) -> CheckResult:
        await asyncio.to_thread(self.graph.ping)
        if self.graph_backend == "memory":
            return CheckResult(status="degraded", detail="in-memory graph (set DSN_NEO4J_URI)")
        return CheckResult(status="ok")
