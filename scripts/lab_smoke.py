#!/usr/bin/env python3
"""End-to-end smoke test of the running virtual lab (``make lab-up`` first).

Checks, against the live gateway backend:
1. all five IoT devices and the status node are discovered (telemetry);
2. nmap fingerprints cam-yard's GoAhead 3.6.4 and links it to CVE-2017-17562 (KEV);
3. a single C2 beacon from a quiet device (default sensor-gate) is captured at the
   gateway and re-scores the device immediately (trigger IOC_CONTACT) with the Feodo indicator as evidence.

Exit code 0 on success. Prints measured timings; never invents numbers.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API = f"http://127.0.0.1:{os.environ.get('DSN_BACKEND_HOST_PORT', '8000')}"
DEVICES = {"cam-front", "cam-yard", "thermo-hall", "plug-lab", "sensor-gate", "status-node"}
C2 = "162.243.103.246"


def get(path: str) -> Any:
    with urllib.request.urlopen(API + path, timeout=10) as resp:  # noqa: S310 - local API
        return json.load(resp)


def wait(what: str, check: Any, timeout: float) -> Any:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            result = check()
        except OSError:
            result = None
        if result:
            print(f"ok   {what} ({time.monotonic() - start:.1f} s)")
            return result
        time.sleep(3)
    sys.exit(f"FAIL {what}: not within {timeout:.0f} s")


def by_host() -> dict[str, dict[str, Any]]:
    return {d["hostname"]: d for d in get("/api/devices") if d.get("hostname")}


def main() -> None:
    wait("6 lab clients discovered", lambda: DEVICES <= set(by_host()), 180)

    def vulncam() -> bool:
        cam = get(f"/api/devices/{by_host()['cam-yard']['node_id']}")["device"]
        return any(s.get("product") == "GoAhead WebServer" for s in cam.get("services", []))

    # On a fresh lab the first scheduled scan runs ~5 min after start.
    wait("nmap fingerprints cam-yard as GoAhead", vulncam, 600)
    cves = get("/api/intel/cves?cpe=cpe:2.3:a:embedthis:goahead:3.6.4:*:*:*:*:*:*:*")
    if not any(c["cve"] == "CVE-2017-17562" and c["kev"] for c in cves):
        sys.exit("FAIL GoAhead 3.6.4 not linked to KEV CVE-2017-17562")
    print("ok   GoAhead 3.6.4 -> CVE-2017-17562 (CISA KEV)")

    # A device that hasn't contacted the C2 yet: only first contacts with a known
    # indicator trigger the immediate check (later ones wait for the re-score).
    victim = os.environ.get("LAB_SMOKE_DEVICE", "sensor-gate")
    node = by_host()[victim]["node_id"]
    started = get(f"/api/risk/{node}").get("latest", {}).get("ts", "")
    sent = time.monotonic()
    subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(ROOT / "scripts" / "tasks.py"), "lab-attack", "c2", victim],
        check=True,
    )

    def correlated() -> dict[str, Any] | None:
        for entry in get(f"/api/risk/{node}").get("history", []):
            if entry.get("trigger") == "IOC_CONTACT" and entry.get("ts", "") > started:
                return dict(entry)
        return None

    decision = wait(f"C2 beacon re-scores {victim} (IOC_CONTACT)", correlated, 180)
    intel = next(f for f in decision["factors"] if f["name"] == "threat_intel")
    if C2 not in intel["summary"]:
        sys.exit(f"FAIL threat_intel evidence lacks {C2}: {intel['summary']}")
    print(
        f"ok   {victim} {decision['score']} {decision['level']} ({decision['action']}); "
        f"{intel['summary']}; {time.monotonic() - sent:.1f} s after the beacon command "
        "started (it sends 5 beacons 3 s apart; traffic windows are 60 s)"
    )


if __name__ == "__main__":
    main()
