#!/usr/bin/env python3
"""Rebuild /fixtures from real public feeds (stdlib only).

Downloads CISA KEV, NVD CVE records, MITRE ATT&CK (enterprise + ICS) and the
Feodo Tracker blocklist, then keeps a small, IoT-relevant subset so tests and
offline mode stay fast and deterministic. abuse.ch URLhaus/ThreatFox and the
dark-web samples are NOT built here: those APIs need credentials, so their
fixtures are hand-written synthetic data (see fixtures/README.md).

Usage: python scripts/build_fixtures.py [--nvd-api-key KEY]
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# IoT / edge-device CVEs, plus Log4Shell as a non-IoT control. All but
# CVE-2017-17215 are in KEV (checked 2026-10-02); that one is the "NVD-only,
# not known-exploited" case.
CVES = [
    "CVE-2023-1389",  # TP-Link Archer AX21 command injection (Mirai)
    "CVE-2021-36260",  # Hikvision camera command injection
    "CVE-2017-17215",  # Huawei HG532 RCE (Satori/Mirai) - not in KEV
    "CVE-2014-8361",  # Realtek SDK miniigd UPnP RCE
    "CVE-2021-44228",  # Log4Shell
    "CVE-2017-17562",  # Embedthis GoAhead < 3.6.5 RCE (virtual lab "cam-yard")
]

# ATT&CK objects relevant to IoT/MQTT behavior detection, by external ID or name.
TECHNIQUES = {
    "T1046", "T1110", "T1110.001", "T1498", "T1499", "T1595", "T1595.001", "T1190",
    "T1071", "T1071.001", "T1557", "T1040", "T1078", "T1105", "T1059.004",
    "T0814", "T0886", "T0846", "T0866",
    "T1692", "T1692.001",  # ICS Command Message (replaced revoked T0855)
}
SOFTWARE = {"Emotet", "QakBot", "BlackEnergy", "Industroyer", "VPNFilter", "Mirai", "Cyclops Blink"}
GROUPS = {"Sandworm Team", "APT28"}


def get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "dsn-fixture-builder/0.1", **(headers or {})})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URLs
        return json.load(resp)


def write(rel: str, data: Any) -> None:
    path = FIXTURES / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"wrote {path.relative_to(ROOT)}")


def build_kev() -> None:
    kev = get_json(KEV_URL)
    items = [v for v in kev["vulnerabilities"] if v["cveID"] in CVES]
    missing = set(CVES) - {v["cveID"] for v in items}
    if missing:
        print(f"warning: not in KEV: {sorted(missing)}")
    write("kev/kev.sample.json", {**{k: kev[k] for k in kev if k != "vulnerabilities"}, "count": len(items), "vulnerabilities": items})


def build_nvd(api_key: str | None) -> None:
    headers = {"apiKey": api_key} if api_key else {}
    vulns: list[Any] = []
    last: dict[str, Any] = {}
    for cve in CVES:
        last = get_json(f"{NVD_URL}?cveId={cve}", headers)
        vulns.extend(last["vulnerabilities"])
        time.sleep(0.7 if api_key else 6.5)  # NVD: 5 req/30s without a key, 50 with
    write(
        "nvd/nvd.sample.json",
        {
            "resultsPerPage": len(vulns),
            "startIndex": 0,
            "totalResults": len(vulns),
            "format": last.get("format", "NVD_CVE"),
            "version": last.get("version", "2.0"),
            "timestamp": last.get("timestamp"),
            "vulnerabilities": vulns,
        },
    )


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in {"mitre-attack", "mitre-ics-attack"}:
            return str(ref.get("external_id"))
    return None


def build_attack() -> None:
    keep: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []
    support: dict[str, dict[str, Any]] = {}
    revoked_sample: dict[str, Any] | None = None
    for domain in ("enterprise-attack", "ics-attack"):
        bundle = get_json(ATTACK_URL.format(domain=domain))
        for obj in bundle["objects"]:
            otype = obj["type"]
            if otype in {"identity", "marking-definition"}:
                support[obj["id"]] = obj
            elif otype == "relationship":
                relationships.append(obj)
            elif otype == "attack-pattern":
                if obj.get("revoked") and revoked_sample is None:
                    revoked_sample = obj
                elif _external_id(obj) in TECHNIQUES and not obj.get("revoked"):
                    keep[obj["id"]] = obj
            elif otype in {"malware", "tool"} and obj.get("name") in SOFTWARE:
                keep[obj["id"]] = obj
            elif otype == "intrusion-set" and obj.get("name") in GROUPS:
                keep[obj["id"]] = obj
    rels = [r for r in relationships if r["source_ref"] in keep and r["target_ref"] in keep]
    objects = list(support.values()) + list(keep.values()) + rels
    if revoked_sample:
        objects.append(revoked_sample)  # lets tests prove revoked objects are skipped
    write(
        "attack/attack.sample.json",
        {"type": "bundle", "id": "bundle--6b3f4c1e-5f0e-4e0a-9d6b-0c0de0f1a7a1", "objects": objects},
    )


def build_feodo() -> None:
    write("feodo/ipblocklist.sample.json", get_json(FEODO_URL))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvd-api-key")
    parser.add_argument("--only", choices=["kev", "attack", "feodo", "nvd"], action="append")
    args = parser.parse_args()
    only = set(args.only or ["kev", "attack", "feodo", "nvd"])
    if "kev" in only:
        build_kev()
    if "attack" in only:
        build_attack()
    if "feodo" in only:
        build_feodo()
    if "nvd" in only:
        build_nvd(args.nvd_api_key)
    print(f"done at {datetime.now(UTC).isoformat()}")


if __name__ == "__main__":
    main()
