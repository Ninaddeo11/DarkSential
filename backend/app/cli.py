"""Command line: ``python -m app.cli <command>``.

ingest [FEED ...]        run feeds now (all enabled feeds if none given)
age                      run indicator aging
related IOC              related threats for an IP/domain/URL/hash
cves CPE                 CVEs affecting a CPE 2.3 string
extract TEXT             run the NLP extractor
demo-phase1              offline end-to-end demo (fixtures -> STIX -> graph -> queries)
"""

from __future__ import annotations

import argparse
import json
import sys
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
    args = parser.parse_args(argv)

    settings = get_settings()
    # Logs go to stderr so command output on stdout stays machine-readable.
    configure_logging(
        "WARNING", json_output=False, secret_values=settings.secret_values(), stream=sys.stderr
    )
    if args.cmd == "demo-phase1":
        demo_phase1(settings)
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
    finally:
        rt.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
