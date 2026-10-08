#!/usr/bin/env python3
"""Live end-to-end timings in the virtual lab (run `make lab-up` first).

    cd backend && uv run python ../scripts/lab_eval.py [--runs 3]

Per run, against the running gateway backend (real packets, real broker, real
nftables), it measures with the wall clock of this host (the containers share it):

* flood_detect_s      flood command start -> ANOMALY_DETECTED for the device (Socket.IO)
* c2_rescore_s        C2 beacon start -> IOC_CONTACT risk assessment for the device
* auto_quarantine_s   C2 beacon + flood start -> QUARANTINE_STARTED by system:risk-engine
* quarantine_apply_ms operator API call -> the device IP is in the nft quarantine set
* release_apply_ms    release API call -> IP gone from the set
* reconnect_s         release -> the device's next MQTT CONNECT in the broker log
                      (whole seconds: the broker log has 1 s resolution)
* recovery_s          quarantine expiry -> DEVICE_RESTORED (auto-recovery)

Rows go to docs/evaluation/phase7/lab_runs.csv. Nothing is estimated: a step that
doesn't happen within its timeout is recorded as empty, with the reason.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PORT = os.environ.get("DSN_BACKEND_HOST_PORT", "8000")
API = f"http://127.0.0.1:{PORT}"
# Live events through nginx, as a browser receives them (allowed CORS origin).
LIVE = f"http://127.0.0.1:{os.environ.get('DSN_FRONTEND_HOST_PORT', '5173')}"
OUT = ROOT / "docs" / "evaluation" / "phase7" / "lab_runs.csv"
COMPOSE = [
    "docker", "compose", "--env-file", str(ROOT / ".env"),
    "-f", str(ROOT / "infra" / "docker-compose.yml"),
    "-f", str(ROOT / "infra" / "docker-compose.lab.yml"),
]  # fmt: skip
FEODO = json.loads((ROOT / "fixtures" / "feodo" / "ipblocklist.sample.json").read_text())
C2_IPS = sorted(str(r["ip_address"]) for r in FEODO)


def env_value(key: str) -> str:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    sys.exit(f"{key} missing in .env")


def http(method: str, path: str, token: str | None = None, body: Any = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)  # noqa: S310 - local API
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - local API
        return json.load(resp)


class Live:
    """Socket.IO listener recording (wall time, event) for every live event."""

    def __init__(self, token: str) -> None:
        import socketio

        self.events: list[tuple[float, dict[str, Any]]] = []
        self.lock = threading.Lock()
        self.client = socketio.Client(reconnection=True)
        self.client.on("events", self._on)
        self.client.connect(
            LIVE,
            socketio_path="api/socket.io",
            transports=["websocket"],
            auth={"token": token, "after_seq": 10**9},
            wait_timeout=10,
        )

    def _on(self, batch: list[dict[str, Any]]) -> None:
        now = time.time()
        with self.lock:
            self.events += [(now, e) for e in batch]

    def wait(self, pred: Any, since: float, timeout: float) -> float | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                hits = [t for t, e in self.events if t >= since and pred(e)]
            if hits:
                return min(hits)
            time.sleep(0.05)
        return None


def lab_attack(scenario: str, device: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, str(ROOT / "scripts" / "tasks.py"), "lab-attack", scenario, device],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip


def nft_has(ip: str) -> bool:
    out = subprocess.run(  # noqa: S603 - fixed argv
        ["docker", "exec", "dsn-backend-1", "nft", "list", "set", "inet", "dsn", "quarantine_v4"],
        capture_output=True, text=True, check=False,
    ).stdout  # fmt: skip
    return ip in out


def poll(pred: Any, timeout: float, interval: float = 0.1) -> float | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return time.time()
        time.sleep(interval)
    return None


def broker_connect_after(user: str, ip: str, since: float, timeout: float) -> float | None:
    """Wall time of the first broker 'New client connected from <ip>' after `since`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = subprocess.run(  # noqa: S603 - fixed argv
            ["docker", "exec", "dsn-mosquitto-1", "sh", "-c", "tail -n 400 /mosquitto/log/mosquitto.log"],
            capture_output=True, text=True, check=False,
        ).stdout  # fmt: skip
        for line in log.splitlines():
            if f"New client connected from {ip}:" in line and f"u'{user}'" in line:
                ts = (
                    datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")
                    .replace(tzinfo=UTC)
                    .timestamp()
                )
                if ts >= int(since):
                    return ts
        time.sleep(1)
    return None


def run_once(i: int, live: Live, token: str, devices: dict[str, dict[str, Any]]) -> dict[str, Any]:
    row: dict[str, Any] = {"run": i, "started": datetime.now(UTC).isoformat(timespec="seconds")}
    notes = []

    # 1. flood -> detection (plug-lab)
    plug = devices["plug-lab"]
    t0 = time.time()
    proc = lab_attack("flood", "plug-lab")
    hit = live.wait(
        lambda e: e["type"] == "ANOMALY_DETECTED" and e["node_id"] == plug["node_id"], t0, 200
    )
    row["flood_detect_s"] = round(hit - t0, 1) if hit else None
    proc.wait()

    # 2. C2 beacon -> IOC_CONTACT re-score (a device that hasn't seen this C2 IP yet)
    victim = ["sensor-gate", "thermo-hall", "cam-front", "status-node", "cam-yard"][i % 5]
    node = devices[victim]["node_id"]
    ip = C2_IPS[i % len(C2_IPS)]
    t0 = time.time()
    subprocess.run(  # noqa: S603 - fixed argv
        [*COMPOSE, "exec", "-T", "--user", "10001", victim, "python", "-m", "app.lab", "attack",
         "c2", "--target", f"{ip}:8080", "--count", "1", "--interval", "0"],
        capture_output=True, check=False,
    )  # fmt: skip

    def ioc_assessed() -> bool:
        hist = http("GET", f"/api/risk/{node}", token).get("history", [])
        return any(
            h.get("trigger") == "IOC_CONTACT"
            and datetime.fromisoformat(h["ts"].replace("Z", "+00:00")).timestamp() >= t0 - 1
            for h in hist
        )

    hit = poll(ioc_assessed, 150, 1.0)
    row["c2_rescore_s"] = round(hit - t0, 1) if hit else None
    row["c2_device"] = victim
    # An unknown device contacting a known C2 is critical *with* evidence of compromise,
    # so the engine may quarantine it: record that, then release it for the next steps.
    victim_q = [q for q in http("GET", "/api/quarantines?status=active", token) if q["node_id"] == node]
    row["c2_auto_quarantined"] = bool(victim_q)
    for q in victim_q:
        http("POST", f"/api/quarantines/{q['id']}/release", token, {"reason": "lab eval cleanup"})

    # 3. operator quarantine / release on the real firewall (plug-lab)
    q_ip = plug["ip"]
    t0 = time.time()
    q = http("POST", "/api/quarantines", token,
             {"node_id": plug["node_id"], "reason": f"lab eval run {i}", "minutes": 1})  # fmt: skip
    hit = poll(lambda: nft_has(q_ip), 10, 0.02)
    row["quarantine_apply_ms"] = round((hit - t0) * 1000) if hit else None

    # 4. auto-recovery at expiry (1-minute quarantine)
    expires = datetime.fromisoformat(str(q["expires_at"]).replace("Z", "+00:00")).timestamp()
    hit = live.wait(
        lambda e: e["type"] == "DEVICE_RESTORED" and e["node_id"] == plug["node_id"], t0, 200
    )
    row["recovery_s"] = round(hit - expires, 1) if hit else None
    released_at = hit
    gone = poll(lambda: not nft_has(q_ip), 10, 0.05)
    row["release_apply_ms"] = round((gone - released_at) * 1000) if gone and released_at else None
    if released_at:
        rc = broker_connect_after("plug-lab", q_ip, released_at, 150)
        # The broker log has 1 s timestamps: a reconnect in the same second as the
        # release reads as 0 (i.e. "within 1 s"), never as a sub-second value.
        row["reconnect_s"] = max(0, round(rc - int(released_at))) if rc else None
    else:
        notes.append("no DEVICE_RESTORED")

    # 5. corroborated compromise -> automatic quarantine by the risk engine
    #    (plug-lab, a C2 IP it hasn't contacted before + an MQTT flood)
    t0 = time.time()
    subprocess.run(  # noqa: S603 - fixed argv
        [*COMPOSE, "exec", "-T", "--user", "10001", "plug-lab", "python", "-m", "app.lab",
         "attack", "c2", "--target", f"{C2_IPS[(i + 3) % len(C2_IPS)]}:8080", "--count", "1",
         "--interval", "0"],
        capture_output=True, check=False,
    )  # fmt: skip
    flood = lab_attack("flood", "plug-lab")
    hit = live.wait(
        lambda e: (
            e["type"] == "QUARANTINE_STARTED"
            and e["node_id"] == plug["node_id"]
            and e["payload"].get("actor") == "system:risk-engine"
        ),
        t0,
        240,
    )
    row["auto_quarantine_s"] = round(hit - t0, 1) if hit else None
    if not hit:
        notes.append("no automatic quarantine")
    flood.wait()
    for q in http("GET", "/api/quarantines?status=active", token):  # tidy up for the next run
        if q["node_id"] == plug["node_id"]:
            http(
                "POST", f"/api/quarantines/{q['id']}/release", token, {"reason": "lab eval cleanup"}
            )
    poll(lambda: not nft_has(q_ip), 10, 0.1)
    row["notes"] = "; ".join(notes)
    return row


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    token = http("POST", "/api/auth/login", body={"secret": env_value("DSN_ADMIN_TOKEN")})[
        "access_token"
    ]
    devices = {d["hostname"]: d for d in http("GET", "/api/devices", token) if d.get("hostname")}
    live = Live(token)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    try:
        for i in range(args.runs):
            row = run_once(i, live, token, devices)
            print(json.dumps(row), flush=True)
            rows.append(row)
            # Rewrite after every run, so an interrupted session keeps what finished.
            fields = list(dict.fromkeys(k for r in rows for k in r))
            with OUT.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
    finally:
        live.client.disconnect()
    print(f"wrote {OUT.relative_to(ROOT)} ({len(rows)} runs)", flush=True)


if __name__ == "__main__":
    main()
