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
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
        update={"offline_mode": True, "database_url": "sqlite://", "scheduler_enabled": False}
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
