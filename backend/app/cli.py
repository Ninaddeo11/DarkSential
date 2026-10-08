"""Command line: ``python -m app.cli <command>``.

ingest [FEED ...]        run feeds now (all enabled feeds if none given)
age                      run indicator aging
related IOC              related threats for an IP/domain/URL/hash
cves CPE                 CVEs affecting a CPE 2.3 string
extract TEXT             run the NLP extractor
demo-phase1              offline end-to-end demo (fixtures -> STIX -> graph -> queries)
devices                  list the device registry
approve NODE_ID          mark a device approved (trusted)
discover-xml FILE        load an nmap XML scan into the registry
scan [--profile P]       nmap scan of the lab CIDR (DRY_RUN: prints the plan only)
replay FILE              feed a .jsonl (TrafficEvent per line) or .pcap through the pipeline
train-model              (re)train and sign the Isolation Forest
rules                    list detection rules and their ATT&CK links
demo-phase2              offline devices + behavior demo (nmap fixture + simulated attacks)
risk NODE_ID             assess and explain one device now
demo-phase3              offline explainable-risk demo
quarantine NODE_ID [MIN]  quarantine a device (DRY_RUN: planned only)
release NODE_ID          release a device's active quarantine
audit [--verify]         show / verify the hash-chained audit log
demo-phase4              offline quarantine / recovery demo
demo-phase5              offline IoT demo (telemetry, signed commands + acks, broker log)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.feeds.config import load_feeds_config
from app.runtime import LabRuntime

DEMO_RULE = (
    "mqtt_connect_flood",
    ["T1498", "T1499"],
    "Sustained MQTT CONNECT flood exhausts broker resources: Network DoS (T1498) "
    "and Endpoint DoS (T1499).",
)


def _dump(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _runtime(settings: Settings) -> LabRuntime:
    rt = LabRuntime.build(
        settings.model_copy(update={"scheduler_enabled": False}),
        load_feeds_config(settings.feeds_config_path),
    )
    rt.graph.ensure_schema()
    return rt


def _print_runs(rt: LabRuntime, names: list[str]) -> None:
    runs = [rt.runner.run(n) for n in names] if names else rt.runner.run_all()
    print(
        f"{'feed':<14}{'mode':<8}{'status':<9}{'objects':>8}{'rejected':>9}{'nodes':>7}{'edges':>7}"
    )
    for r in runs:
        print(
            f"{r.feed:<14}{r.mode:<8}{r.status:<9}{r.objects:>8}{r.rejected:>9}"
            f"{r.nodes:>7}{r.edges:>7}" + (f"  {r.error}" if r.error else "")
        )


def demo_phase1(settings: Settings) -> None:
    settings = settings.model_copy(
        update={
            "offline_mode": True,
            "database_url": "sqlite://",
            "scheduler_enabled": False,
            "iforest_autotrain": False,
            "xgb_autotrain": False,
        }
    )
    rt = _runtime(settings)
    try:
        print(f"== Ingest (offline fixtures -> STIX 2.1 -> {rt.graph_backend} graph)")
        _print_runs(rt, [])
        print("\n== Graph counts")
        _dump(rt.graph.counts())

        print("\n== related_threats('162.243.103[.]246')  (Feodo C2 -> Emotet -> ATT&CK)")
        for t in rt.graph.related_threats("162.243.103[.]246"):
            chain = " -> ".join(f"{s.via + ' ' if s.via else ''}{s.label}:{s.name}" for s in t.path)
            print(f"  [{t.hops} hop, conf {t.confidence}] {chain}")

        cpe = "cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.1:*:*:*:*:*:*:*"
        print(f"\n== cves_for_cpe('{cpe}')")
        for m in rt.graph.cves_for_cpe(cpe):
            print(f"  {m.cve} cvss={m.cvss_score} kev={m.kev} match={m.match}")

        rule_id, techniques, rationale = DEMO_RULE
        missing = rt.graph.link_rule(rule_id, techniques, rationale)
        print(f"\n== techniques_for_behavior('{rule_id}')  (missing: {missing or 'none'})")
        for tech in rt.graph.techniques_for_behavior(rule_id):
            print(f"  {tech.external_id} {tech.name} tactics={tech.tactics}")

        text = "Loader at hxxp://192.0.2[.]45/x, uses CVE-2023-1389 and T1110.001; QBot crew."
        print(f"\n== extract({text!r})")
        try:
            extractor = rt.runner.extractor()
        except ImportError as exc:
            print(f"  skipped: spaCy cannot load on this host ({type(exc).__name__})")
            print("\nPhase 1 demo finished WITHOUT NLP (run `make docker-demo-phase1`)")
            return
        for e in extractor.extract(text).entities:
            print(f"  {e.type:<17}{e.value:<20} conf={e.confidence} span={e.start}-{e.end}")
        print("\nPhase 1 demo OK")
    finally:
        rt.stop()


def _replay(rt: LabRuntime, path: Path) -> list[Any]:
    from app.behavior.events import TrafficEvent

    if path.suffix == ".pcap":
        from app.behavior.pcap import events_from_pcap

        events = events_from_pcap(path)
    else:
        lines = path.read_text(encoding="utf-8").splitlines()
        events = [TrafficEvent.model_validate_json(line) for line in lines if line.strip()]
    return rt.pipeline.ingest(events) + rt.pipeline.flush()


def demo_phase2(settings: Settings) -> None:
    from app.detect.nmap_scan import parse_nmap_xml, plan
    from app.simulation.traffic import SimDevice, TrafficSimulator, merge

    settings = settings.model_copy(
        update={
            "offline_mode": True,
            "database_url": "sqlite://",
            "scheduler_enabled": False,
            "models_dir": Path(tempfile.mkdtemp(prefix="dsn-models-")),
            "iforest_autotrain": True,
            "xgb_autotrain": False,
        }
    )
    rt = _runtime(settings)
    try:
        start = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)
        print("== ATT&CK import + rule -> technique links")
        rt.runner.run("mitre_attack")
        missing = rt.link_rules()
        for rule in rt.rules.rules:
            linked = [t.external_id for t in rt.graph.techniques_for_behavior(rule.id)]
            print(f"  {rule.id:<28}{rule.severity:<9}{', '.join(linked) or '-'}")
        print(f"  missing techniques: {missing or 'none'}")

        print("\n== Discovery: nmap fixture (active scans under DRY_RUN only print the plan)")
        print("  plan:", " ".join(plan(settings, "service")))
        fixture = settings.fixtures_dir / "events" / "lab-scan.nmap.xml"
        for obs in parse_nmap_xml(fixture.read_bytes()):
            rt.registry.observe(obs.model_copy(update={"ts": start}))
        for d in rt.registry.list():
            top = d.cpes[0]["cpe"] if d.cpes else "-"
            vendor = (d.vendor or "-")[:28]
            print(f"  {d.node_id}  {d.ip or '-':<15}{vendor:<30}{d.trust:<9}{top}")

        print("\n== Behavior: 45 min normal traffic, then attacks (seed 42)")
        sim = TrafficSimulator(seed=42)
        t_attack = start + timedelta(minutes=45)
        rogue = SimDevice("rogue", "02:00:5e:aa:bb:cc", "192.168.50.66", "esp32_sensor")
        stream = merge(
            sim.normal(start, 50),
            sim.mqtt_flood(sim.device("esp32-node"), t_attack, minutes=2, per_minute=500),
            sim.wildcard_subscribe(sim.device("plug-desk"), t_attack + timedelta(minutes=1)),
            sim.restricted_publish(sim.device("plug-desk"), t_attack + timedelta(minutes=2)),
            sim.brute_force(sim.device("cam-front"), t_attack + timedelta(minutes=1)),
            sim.port_scan(sim.device("thermo-hall"), t_attack + timedelta(minutes=3)),
            sim.port_scan(rogue, t_attack + timedelta(minutes=2), ports=120),
        )
        names = {d.ip: d.name for d in (*sim.fleet, rogue)}
        labels: dict[tuple[str, datetime], set[str]] = {}
        for le in stream:
            ws = le.event.ts.replace(second=0, microsecond=0)
            labels.setdefault((le.device, ws), set()).add(le.label)
        scorer = (
            "Isolation Forest + z-scores"
            if rt.pipeline.scorer.model
            else "z-scores only (scikit-learn unavailable on this host)"
        )
        print(f"  scorer: {scorer};  events: {len(stream)}")
        results = rt.pipeline.ingest([le.event for le in stream]) + rt.pipeline.flush()
        flagged = [r for r in results if r.anomaly.is_anomaly or r.rule_hits]
        print(f"  windows scored: {len(results)}   flagged: {len(flagged)}\n")
        print(f"  {'time':<6}{'device':<13}{'ground truth':<34}{'score':>6}  detections")

        def name_of(node_id: str) -> str:
            dev = rt.registry.get(node_id)
            return names.get(dev.ip or "", node_id) if dev else node_id

        for r in flagged:
            name = name_of(r.node_id)
            truth = sorted(labels.get((name, r.window_start), {"?"}) - {"normal"}) or ["normal"]
            hits = ", ".join(f"{h.rule_id}[{'/'.join(h.techniques)}]" for h in r.rule_hits)
            base = "cold" if r.anomaly.cold_start else "warm"
            print(
                f"  {r.window_start:%H:%M} {name:<13}{','.join(truth):<34}"
                f"{r.anomaly.combined:>6.2f}  {hits or 'anomaly'} ({base})"
            )

        attack_windows = {k for k, v in labels.items() if v - {"normal"}}
        caught = {(name_of(r.node_id), r.window_start) for r in flagged}
        print(
            f"\n  attack windows: {len(attack_windows)}, detected: "
            f"{len(attack_windows & caught)}, normal windows flagged: "
            f"{len(caught - attack_windows)}"
        )
        events = Counter(e.type for e in rt.bus.recent(limit=5000))
        print("  events:", dict(sorted(events.items())))
        rogue_view = next((d for d in rt.registry.list() if d.ip == rogue.ip), None)
        if rogue_view:
            print(
                f"  rogue device: {rogue_view.node_id} trust={rogue_view.trust} "
                f"randomized_mac={rogue_view.randomized_mac} vendor={rogue_view.vendor}"
            )
        print("\nPhase 2 demo OK")
    finally:
        rt.stop()


def _print_decision(d: Any, name: str) -> None:
    print(f"\n-- {name} ({d.node_id})")
    print(f"   {d.explanation}")
    print(f"   {'factor':<20}{'value':>7}{'weight':>8}{'contribution':>14}")
    for c in d.contributions:
        print(f"   {c.factor:<20}{c.value:>7.3f}{c.weight:>8.2f}{c.contribution:>14.2f}")
    print(f"   {'= score':<35}{d.score:>14.2f}  ({d.level}, action: {d.action})")
    for path in d.evidence_paths[:2]:
        chain = " -> ".join(f"{s.via + ' ' if s.via else ''}{s.label}:{s.name}" for s in path)
        print(f"   evidence path: {chain}")
    if d.ml:
        shap = ", ".join(f"{k} {v:+.2f}" for k, v in list(d.ml.shap.items())[:3])
        print(f"   ML (comparison only): XGBoost p(attack)={d.ml.probability:.3f}; SHAP: {shap}")


def demo_phase3(settings: Settings) -> None:
    from app.behavior.events import TrafficEvent
    from app.detect.nmap_scan import parse_nmap_xml
    from app.simulation.traffic import TrafficSimulator

    gateway = "192.168.50.1"
    settings = settings.model_copy(
        update={
            "offline_mode": True,
            "database_url": "sqlite://",
            "scheduler_enabled": False,
            "models_dir": Path(tempfile.mkdtemp(prefix="dsn-models-")),
            "iforest_autotrain": True,
            "xgb_autotrain": True,
            "protected_hosts": [ipaddress.ip_address(gateway)],
        }
    )
    rt = _runtime(settings)
    try:
        start = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)
        print("== Threat intel (offline fixtures) + discovery (nmap fixture)")
        for feed in ("mitre_attack", "cisa_kev", "nvd_cve", "feodo", "threatfox"):
            rt.runner.run(feed)
        rt.link_rules()
        for obs in parse_nmap_xml(
            (settings.fixtures_dir / "events" / "lab-scan.nmap.xml").read_bytes()
        ):
            rt.registry.observe(obs.model_copy(update={"ts": start}))
        ml = "XGBoost + SHAP attached" if rt.risk.ml else "no ML stack on this host"
        print(f"  devices: {len(rt.registry.list())}; ML comparison: {ml}")

        print("\n== 40 min baseline traffic, then esp32-node floods MQTT and contacts a Feodo C2")
        sim = TrafficSimulator(seed=7)
        esp = sim.device("esp32-node")
        t_attack = start + timedelta(minutes=40)
        events = [le.event for le in sim.normal(start, 43)]
        events += [le.event for le in sim.mqtt_flood(esp, t_attack, minutes=2, per_minute=500)]
        events.append(
            TrafficEvent(
                ts=t_attack + timedelta(seconds=30),
                src_mac=esp.mac,
                src_ip=esp.ip,
                dst_ip="162.243.103.246",
                dst_port=8080,
                proto="tcp",
                bytes=74,
            )
        )
        rt.pipeline.ingest(events)
        rt.pipeline.flush()
        names = {d.ip: d.name for d in sim.fleet} | {gateway: "archer-gw", "192.168.50.2": "broker"}

        print("\n== Risk (latest decision per device, highest first)")
        print(f"  {'device':<13}{'score':>6}  {'level':<9}{'action':<19}top factor")
        rows = rt.risk.latest_all()
        for row in rows:
            dev = rt.registry.get(row["node_id"])
            top = max(row["contributions"], key=lambda c: c["contribution"])
            label = f"{top['factor']} +{top['contribution']:g}" if top["contribution"] else "-"
            print(
                f"  {names.get((dev.ip or '') if dev else '', row['node_id']):<13}"
                f"{row['score']:>6.1f}  {row['level']:<9}{row['action']:<19}{label}"
            )

        for ip, name in ((gateway, "archer-gw (protected host)"), (esp.ip, "esp32-node")):
            node_id = rt.registry.resolve(ip=ip)
            decision = (
                rt.risk.assess(node_id, now=t_attack + timedelta(minutes=2)) if node_id else None
            )
            if decision:
                _print_decision(decision, name)
        events_seen = Counter(e.type for e in rt.bus.recent(limit=5000))
        print("\n  events:", dict(sorted(events_seen.items())))
        print("\nPhase 3 demo OK")
    finally:
        rt.stop()


def demo_phase4(settings: Settings) -> None:
    import yaml

    from app.behavior.events import TrafficEvent
    from app.core.config import BACKEND_ROOT
    from app.detect.observations import Observation
    from app.mqtt.commands import COMMAND_TOPIC, NullPublisher
    from app.response.drivers import DryRunDriver
    from app.response.service import QuarantineRefused
    from app.simulation.traffic import TrafficSimulator

    tmp = Path(tempfile.mkdtemp(prefix="dsn-demo4-"))
    risk_cfg = yaml.safe_load((BACKEND_ROOT / "config" / "risk.yaml").read_text(encoding="utf-8"))
    risk_cfg["thresholds"] = {"low": 0, "medium": 20, "high": 30, "critical": 40}
    (tmp / "risk.yaml").write_text(yaml.safe_dump(risk_cfg), encoding="utf-8")
    settings = settings.model_copy(
        update={
            "offline_mode": True,
            "database_url": "sqlite://",
            "scheduler_enabled": False,
            "iforest_autotrain": False,
            "xgb_autotrain": False,
            "protected_hosts": [ipaddress.ip_address("192.168.50.1")],
            "risk_config_path": tmp / "risk.yaml",
            "quarantine_minutes": 10,
            "mqtt_command_key": SecretStr("demo-status-node-key-0123456789abcdef"),
            "models_dir": tmp / "models",
        }
    )
    rt = _runtime(settings)
    try:
        t0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
        print(
            f"== Enforcement driver: {rt.response.driver.name} "
            f"(DRY_RUN={settings.dry_run}; nothing touches the network)"
        )
        print(f"   reconcile at startup: {rt.response.reconcile(now=t0)}")
        rt.runner.run("feodo")
        gw = rt.registry.observe(
            Observation(source="arp", ts=t0, mac="50:c7:bf:00:00:01", ip="192.168.50.1")
        )

        print("\n== 1. Manual quarantine of the gateway is refused (protected host)")
        try:
            rt.response.quarantine(gw.node_id if gw else "", "test", actor="cli", now=t0)
        except QuarantineRefused as exc:
            print(f"   refused: {exc.reason}")

        print(
            "\n== 2. esp32-node floods MQTT and contacts a Feodo C2 -> CRITICAL -> auto quarantine"
        )
        sim = TrafficSimulator(seed=11)
        esp = sim.device("esp32-node")
        events = [le.event for le in sim.mqtt_flood(esp, t0, minutes=1)]
        events.append(
            TrafficEvent(
                ts=t0 + timedelta(seconds=20),
                src_mac=esp.mac,
                src_ip=esp.ip,
                dst_ip="162.243.103.246",
                dst_port=8080,
                proto="tcp",
            )
        )
        rt.pipeline.ingest(events)
        rt.pipeline.flush()
        for q in rt.response.list(status="active"):
            print(
                f"   quarantine #{q['id']}: {q['ip']} by {q['actor']} until "
                f"{q['expires_at']:%H:%M} UTC; reason: {q['reason']}"
            )
        driver = rt.response.driver
        if isinstance(driver, DryRunDriver):
            for line in driver.planned[-1:]:
                print(f"   {line}")

        print("\n== 3. Drift: the element vanished from the firewall; reconcile restores it")
        if esp.ip in driver.active():
            driver.release(esp.ip)
        diff = rt.response.reconcile(now=t0 + timedelta(minutes=1))
        print(f"   added back: {diff['added']}; in sync: {diff['in_sync']}")

        print("\n== 4. Expiry -> automatic recovery")
        released = rt.response.expire_due(t0 + timedelta(minutes=11))
        print(f"   released {released} quarantine(s); firewall now: {sorted(driver.active())}")

        pub = rt.response.commander.publisher
        if isinstance(pub, NullPublisher):
            cmds = [json.loads(p) for topic, p in pub.sent if topic == COMMAND_TOPIC]
            print(
                "\n== Status-node MQTT commands (HMAC-signed):", ", ".join(c["cmd"] for c in cmds)
            )
            print(
                f"   e.g. {{'cmd': '{cmds[0]['cmd']}', 'node_id': '{cmds[0]['node_id']}', "
                f"'sig': '{cmds[0]['sig'][:16]}...'}}"
            )

        print("\n== Audit log (hash-chained, newest first)")
        for entry in rt.audit.entries(limit=8):
            print(
                f"   #{entry['id']:<3}{entry['actor']:<22}{entry['action']:<12}"
                f"{entry['outcome']:<9}{entry['hash'][:12]}"
            )
        chain = rt.audit.verify_chain()
        print(
            f"   chain verified: ok={chain.ok}, entries={chain.entries}, head={chain.head[:16]}..."
        )
        seen = Counter(e.type for e in rt.bus.recent(limit=5000))
        print(
            "\n  events:",
            {
                k: v
                for k, v in sorted(seen.items())
                if k.startswith(("QUARANTINE", "RECOVERY", "DEVICE_RESTORED"))
            },
        )
        print("\nPhase 4 demo OK")
    finally:
        rt.stop()


def demo_phase5(settings: Settings) -> None:
    from app.core.config import REPO_ROOT
    from app.lab.status_node import StatusNodeLogic
    from app.mqtt.brokerlog import BrokerLogParser, tail_once
    from app.mqtt.commands import COMMAND_TOPIC, NullPublisher

    key = "demo-status-node-key-0123456789abcdef"
    tmp = Path(tempfile.mkdtemp(prefix="dsn-demo5-"))
    settings = settings.model_copy(
        update={
            "offline_mode": True,
            "database_url": "sqlite://",
            "scheduler_enabled": False,
            "iforest_autotrain": False,
            "xgb_autotrain": False,
            "mqtt_command_key": SecretStr(key),
            "mqtt_broker_log": None,
            "models_dir": tmp / "models",
        }
    )
    rt = _runtime(settings)
    try:
        telemetry = rt.telemetry
        publisher = rt.response.commander.publisher
        if telemetry is None or not isinstance(publisher, NullPublisher):
            raise RuntimeError("demo-phase5 needs the offline runtime (no broker configured)")
        print("== 1. Device telemetry (topic dsn/telemetry/<user>; the broker ACL binds the user)")
        mac = "24:0a:c4:40:00:04"
        good: dict[str, Any] = {
            "v": 1, "mac": mac, "ip": "192.168.50.24", "fw": "0.6.0",
            "uptime_s": 42, "rssi": -58, "heap": 201234, "state": "NORMAL", "seq": 1,
        }  # fmt: skip
        topic = "dsn/telemetry/esp32-node"
        cases: list[tuple[str, str, bytes]] = [
            ("valid", topic, json.dumps(good).encode()),
            ("nested topic", topic + "/x", json.dumps(good).encode()),
            ("oversized", topic, b"{" + b" " * 4096 + b"}"),
            ("rssi out of range", topic, json.dumps(good | {"rssi": 50}).encode()),
            ("markup in fw", topic, json.dumps(good | {"fw": "<script>x</script>"}).encode()),
            ("not json", topic, b"\xff\xfe"),
        ]
        for label, t, payload in cases:
            ok = telemetry.handle(t, payload)
            print(f"   {label:<20} -> {'accepted' if ok else 'rejected'}")
        node = rt.registry.resolve(mac=mac)
        device = rt.registry.get(node) if node else None
        if device is not None:
            attrs = {k: device.attributes.get(k) for k in ("mqtt_user", "fw", "rssi", "state")}
            print(f"   registry: {device.node_id} ip={device.ip} {attrs}")

        print("\n== 2. Signed status-node commands, checked by the virtual status node")
        print("   (app.lab.status_node: the same code the lab's status-node container runs)")
        commander = rt.response.commander
        status_node = StatusNodeLogic(key.encode())

        def node_verdict(cmd: dict[str, Any], now: int) -> str:
            return status_node.handle(json.dumps(cmd).encode(), now)[1]

        sent = commander.send("QUARANTINE", node or "", "critical")
        wire = json.loads(publisher.sent[-1][1])
        now = int(wire["ts"])
        commander.send("ALERT", node or "")
        forged_wire = json.loads(publisher.sent[-1][1]) | {"cmd": "RECOVER"}  # tampered in flight
        trials = [
            ("genuine QUARANTINE", wire, now),
            ("same message replayed", wire, now + 5),
            ("ALERT altered to RECOVER", forged_wire, now),
            ("genuine, delivered 2 min late", wire, now + 120),
        ]
        for label, cmd, at in trials:
            verdict = node_verdict(cmd, at)
            print(f"   {label:<28} -> {verdict}")
            rt.response.on_ack(json.dumps({"id": cmd["id"], "status": verdict}).encode())
        print(f"   command topic: {COMMAND_TOPIC}; sig={sent['sig'][:16]}... ttl={sent['ttl']}s")
        acks = [e for e in rt.audit.entries(limit=20) if e["action"] == "mqtt_ack"]
        for entry in reversed(acks):
            d = entry["details"]
            print(f"   audit: mqtt_ack cmd={d['cmd']:<11} status={d['status']}")

        print("\n== 3. Broker log replay (real eclipse-mosquitto 2.0.22 capture)")
        log_path = REPO_ROOT / "fixtures" / "events" / "mosquitto.sample.log"
        parser = BrokerLogParser(None, frozenset(settings.mqtt_service_clients))
        events = tail_once(log_path, parser)
        kinds = Counter(
            f"{e.mqtt.packet}{'' if e.ok is not False else ' (refused)'}" for e in events if e.mqtt
        )
        print(f"   parsed {len(events)} events: {dict(sorted(kinds.items()))}")
        print("   (the backend's own wildcard subscriptions are excluded as a service client)")
        rt.pipeline.ingest(events)
        hits = {h.rule_id: h for r in rt.pipeline.flush() for h in r.rule_hits}
        for hit in hits.values():
            print(f"   rule {hit.rule_id:<28} {hit.severity:<8} {','.join(hit.techniques)}")
        print(
            "   note: every client in this capture reached the broker via the Docker NAT\n"
            "   address 172.17.0.1, so all activity is attributed to that one source."
        )
        print("\nPhase 5 demo OK")
    finally:
        rt.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ingest = sub.add_parser("ingest")
    ingest.add_argument("feeds", nargs="*")
    sub.add_parser("age")
    related = sub.add_parser("related")
    related.add_argument("ioc")
    cves = sub.add_parser("cves")
    cves.add_argument("cpe")
    extract = sub.add_parser("extract")
    extract.add_argument("text")
    sub.add_parser("demo-phase1")
    sub.add_parser("devices")
    approve = sub.add_parser("approve")
    approve.add_argument("node_id")
    discover = sub.add_parser("discover-xml")
    discover.add_argument("file", type=Path)
    scan_p = sub.add_parser("scan")
    scan_p.add_argument("--profile", choices=["ping", "service"], default="ping")
    replay = sub.add_parser("replay")
    replay.add_argument("file", type=Path)
    sub.add_parser("train-model")
    sub.add_parser("rules")
    sub.add_parser("demo-phase2")
    sub.add_parser("demo-phase3")
    sub.add_parser("demo-phase4")
    sub.add_parser("demo-phase5")
    quar = sub.add_parser("quarantine")
    quar.add_argument("node_id")
    quar.add_argument("minutes", nargs="?", type=int)
    rel = sub.add_parser("release")
    rel.add_argument("node_id")
    aud = sub.add_parser("audit")
    aud.add_argument("--verify", action="store_true")
    risk_p = sub.add_parser("risk")
    risk_p.add_argument("node_id")
    args = parser.parse_args(argv)

    settings = get_settings()
    # Logs go to stderr so command output on stdout stays machine-readable.
    configure_logging(
        "WARNING", json_output=False, secret_values=settings.secret_values(), stream=sys.stderr
    )
    if args.cmd == "demo-phase1":
        demo_phase1(settings)
        return 0
    if args.cmd == "demo-phase2":
        demo_phase2(settings)
        return 0
    if args.cmd == "demo-phase3":
        demo_phase3(settings)
        return 0
    if args.cmd == "demo-phase4":
        demo_phase4(settings)
        return 0
    if args.cmd == "demo-phase5":
        demo_phase5(settings)
        return 0
    if args.cmd == "scan":
        from app.detect.nmap_scan import scan

        result = scan(settings, args.profile)
        _dump(
            {
                "dry_run": result.dry_run,
                "command": result.command,
                "hosts": len(result.observations),
            }
        )
        return 0
    if args.cmd == "train-model":
        from app.behavior.config import load_behavior_config
        from app.behavior.pipeline import train_model

        model = train_model(load_behavior_config(settings.behavior_config_path))
        model.save(settings.models_dir, settings.device_id_hmac_key.get_secret_value().encode())
        _dump(model.meta)
        return 0

    rt = _runtime(settings)
    try:
        if args.cmd == "ingest":
            _print_runs(rt, args.feeds)
        elif args.cmd == "age":
            _dump(rt.runner.age().model_dump())
        elif args.cmd == "related":
            _dump([t.model_dump() for t in rt.graph.related_threats(args.ioc)])
        elif args.cmd == "cves":
            _dump([m.model_dump() for m in rt.graph.cves_for_cpe(args.cpe)])
        elif args.cmd == "extract":
            _dump(rt.runner.extractor().extract(args.text).model_dump())
        elif args.cmd == "risk":
            decision = rt.risk.assess(args.node_id, trigger="cli")
            if decision is None:
                print(f"unknown device {args.node_id}", file=sys.stderr)
                return 1
            _dump(decision.model_dump(mode="json"))
        elif args.cmd == "quarantine":
            # The firewall table must exist before elements are added (fresh host).
            rt.response.reconcile()
            _dump(
                rt.response.quarantine(
                    args.node_id, "manual (cli)", actor="cli", minutes=args.minutes
                )
            )
        elif args.cmd == "release":
            rt.response.reconcile()
            _dump(rt.response.release_node(args.node_id, actor="cli", reason="manual (cli)"))
        elif args.cmd == "audit":
            _dump(rt.audit.verify_chain().model_dump() if args.verify else rt.audit.entries(50))
        elif args.cmd == "devices":
            _dump([d.model_dump() for d in rt.registry.list()])
        elif args.cmd == "approve":
            _dump(rt.registry.approve(args.node_id).model_dump())
        elif args.cmd == "discover-xml":
            from app.detect.nmap_scan import parse_nmap_xml

            views = [rt.registry.observe(o) for o in parse_nmap_xml(args.file.read_bytes())]
            _dump([v.node_id for v in views if v])
        elif args.cmd == "replay":
            _dump(
                [
                    {
                        "node_id": r.node_id,
                        "window_start": r.window_start,
                        "anomaly": r.anomaly.combined,
                        "rules": [h.rule_id for h in r.rule_hits],
                    }
                    for r in _replay(rt, args.file)
                    if r.anomaly.is_anomaly or r.rule_hits
                ]
            )
        elif args.cmd == "rules":
            rt.link_rules()
            _dump(
                [
                    {
                        "id": r.id,
                        "severity": r.severity,
                        "techniques": r.techniques,
                        "rationale": r.rationale,
                    }
                    for r in rt.rules.rules
                ]
            )
    finally:
        rt.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
