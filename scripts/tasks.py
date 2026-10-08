#!/usr/bin/env python3
"""Cross-platform task runner (stdlib only). The Makefile delegates here.

Usage: python scripts/tasks.py <task>    e.g.  python scripts/tasks.py demo-phase0
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
COMPOSE = ["docker", "compose", "--env-file", str(ROOT / ".env"), "-f", str(ROOT / "infra" / "docker-compose.yml")]
NPM = "npm.cmd" if os.name == "nt" else "npm"

TASKS: dict[str, Callable[[], None]] = {}


def task(fn: Callable[[], None]) -> Callable[[], None]:
    TASKS[fn.__name__.replace("_", "-")] = fn
    return fn


def run(cmd: list[str], cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print(f"$ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=cwd, check=True, env=env)


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        sys.exit(f"'{tool}' not found on PATH")


# Virtual lab clients (infra/docker-compose.lab.yml); the broker's lab address goes
# into its certificate so lab clients verify it by IP.
LAB_CLIENTS = ["cam-front", "cam-yard", "thermo-hall", "plug-lab", "sensor-gate", "rogue-sensor"]
LAB_BROKER_IP = "10.77.2.10"
API_PORT = os.environ.get("DSN_BACKEND_HOST_PORT", "8000")
LAB_COMPOSE = [*COMPOSE, "-f", str(ROOT / "infra" / "docker-compose.lab.yml")]


def _ensure_env() -> Path:
    env_file = ROOT / ".env"
    if not env_file.exists():
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        text = text.replace(
            "DSN_DEVICE_ID_HMAC_KEY=\n", f"DSN_DEVICE_ID_HMAC_KEY={secrets.token_urlsafe(48)}\n"
        )
        text = text.replace("change-me-to-a-long-random-password", secrets.token_urlsafe(24))
        for key in ("DSN_AUTH_JWT_SECRET", "DSN_ADMIN_TOKEN", "DSN_VIEWER_TOKEN"):
            text = text.replace(f"{key}=\n", f"{key}={secrets.token_urlsafe(32)}\n")
        env_file.write_text(text, encoding="utf-8")
        print("created .env with freshly generated secrets")
    # Older .env files predate the Phase 6 auth secrets: add any that are missing
    # or empty (values are never printed).
    lines = env_file.read_text(encoding="utf-8").splitlines()
    added = []
    for key in ("DSN_AUTH_JWT_SECRET", "DSN_ADMIN_TOKEN", "DSN_VIEWER_TOKEN"):
        current = [ln for ln in lines if ln.startswith(f"{key}=")]
        if not current or current[-1] == f"{key}=":
            lines = [ln for ln in lines if not ln.startswith(f"{key}=")]
            lines.append(f"{key}={secrets.token_urlsafe(32)}")
            added.append(key)
    if added:
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"generated missing secrets in .env: {', '.join(added)}")
    return env_file


def _provision_mqtt() -> None:
    """Broker PKI + per-client credentials (idempotent); backend creds into .env."""
    env_file = _ensure_env()
    devices = [a for d in LAB_CLIENTS for a in ("--device", d)]
    run(["uv", "run", "python", "../scripts/mqtt_provision.py", "--host", "mosquitto",
         "--host", "localhost", "--ip", "127.0.0.1", "--ip", LAB_BROKER_IP, *devices],
        cwd=BACKEND)
    creds = json.loads((ROOT / "infra" / "mosquitto" / "credentials.json").read_text("utf-8"))
    env = env_file.read_text(encoding="utf-8")
    for key, value in (("DSN_MQTT_PASSWORD", creds["users"]["dsn-backend"]),
                       ("DSN_MQTT_COMMAND_KEY", creds["command_key"])):
        lines = [ln for ln in env.splitlines() if not ln.startswith(f"{key}=")]
        lines.append(f"{key}={value}")
        env = "\n".join(lines) + "\n"
    env_file.write_text(env, encoding="utf-8")
    print("MQTT provisioned: backend credentials + command key written to .env")


@task
def setup() -> None:
    """Install deps; create .env with generated secrets; provision MQTT TLS + creds."""
    _require("uv")
    run(["uv", "sync", "--frozen", "--all-extras"], cwd=BACKEND)
    run([NPM, "ci"], cwd=FRONTEND)
    _provision_mqtt()


@task
def lint() -> None:
    run(["uv", "run", "ruff", "check", ".", "../api"], cwd=BACKEND)
    run(["uv", "run", "ruff", "format", "--check", ".", "../api"], cwd=BACKEND)


EXPORT_REQS = ["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--no-emit-project", "-q"]


@task
def export_reqs() -> None:
    """Regenerate root requirements.txt (used by Vercel) from backend/uv.lock."""
    run([*EXPORT_REQS, "-o", "../requirements.txt"], cwd=BACKEND)


@task
def gen_types() -> None:
    """Regenerate frontend/src/generated/events.ts from the backend event schema."""
    run(["uv", "run", "python", "../scripts/gen_event_types.py"], cwd=BACKEND)


@task
def typecheck() -> None:
    run(["uv", "run", "mypy"], cwd=BACKEND)
    run([NPM, "run", "typecheck"], cwd=FRONTEND)


@task
def test() -> None:
    run(["uv", "run", "pytest", "--cov", "--cov-report=term-missing"], cwd=BACKEND)


@task
def check() -> None:
    """Everything CI runs."""
    lint()
    typecheck()
    run(["uv", "run", "python", "../scripts/gen_event_types.py", "--check"], cwd=BACKEND)
    test()
    run([NPM, "run", "build"], cwd=FRONTEND)
    run([NPM, "test"], cwd=FRONTEND)


@task
def fmt() -> None:
    run(["uv", "run", "ruff", "check", "--fix", ".", "../api"], cwd=BACKEND)
    run(["uv", "run", "ruff", "format", ".", "../api"], cwd=BACKEND)


@task
def dev_backend() -> None:
    run(["uv", "run", "python", "-m", "app"], cwd=BACKEND)


@task
def dev_frontend() -> None:
    run([NPM, "run", "dev"], cwd=FRONTEND)


@task
def up() -> None:
    run([*COMPOSE, "up", "-d", "--build"])


@task
def down() -> None:
    run([*COMPOSE, "down"])


@task
def lab_up() -> None:
    """Start the virtual lab: broker, gateway backend, 5 IoT devices + status node."""
    _require("docker")
    _require("uv")
    _provision_mqtt()
    run([*LAB_COMPOSE, "up", "-d", "--build", "--wait"])
    # Feeds otherwise first run on their schedule (hours away): load intel now.
    run([*LAB_COMPOSE, "exec", "-T", "--user", "dsn", "backend",
         "python", "-m", "app.cli", "ingest"])
    print(f"virtual lab up: API http://127.0.0.1:{API_PORT}  (lab-status, lab-attack <scenario>)")


@task
def lab_down() -> None:
    """Stop the virtual lab (keeps volumes)."""
    run([*LAB_COMPOSE, "--profile", "attack", "down"])


@task
def lab_status() -> None:
    """Containers + what the backend currently knows about each lab device."""
    run([*LAB_COMPOSE, "ps", "--format", "table {{.Service}}\t{{.State}}\t{{.Status}}"])
    try:
        _, devices = _get(f"http://127.0.0.1:{API_PORT}/api/devices")
    except (urllib.error.URLError, OSError) as exc:
        sys.exit(f"backend not reachable: {exc}")
    for dev in devices if isinstance(devices, list) else []:
        print(f"  {dev.get('ip') or '-':<14}{dev.get('node_id', '')[:20]:<22}"
              f"{dev.get('trust', '')!s:<10}{(dev.get('vendor') or '')[:28]}")


@task
def lab_smoke() -> None:
    """End-to-end check of a running lab (discovery, KEV link, IOC-contact re-score)."""
    run([sys.executable, str(ROOT / "scripts" / "lab_smoke.py")])


LAB_SCENARIOS: dict[str, tuple[str, list[str]]] = {
    # scenario: (service to run it in, app.lab arguments)
    "flood": ("plug-lab", ["attack", "flood", "--per-minute", "500", "--minutes", "2"]),
    "wildcard": ("plug-lab", ["attack", "wildcard", "--seconds", "90"]),
    "restricted": ("plug-lab", ["attack", "restricted", "--count", "10"]),
    "bad-auth": ("thermo-hall", ["attack", "bad-auth", "--attempts", "20"]),
    "c2": ("cam-yard", ["attack", "c2", "--count", "5", "--interval", "3"]),
}


@task
def lab_attack() -> None:
    """Run a lab scenario: lab-attack <rogue|flood|wildcard|restricted|bad-auth|c2> [device]."""
    scenario = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SCENARIO", "")
    if scenario == "rogue":
        run([*LAB_COMPOSE, "--profile", "attack", "up", "-d", "rogue-sensor"])
        return
    if scenario not in LAB_SCENARIOS:
        sys.exit(f"scenario must be one of: rogue, {', '.join(LAB_SCENARIOS)}")
    service, args = LAB_SCENARIOS[scenario]
    if len(sys.argv) > 3:  # optional: make a different lab device misbehave
        service = sys.argv[3]
        if service not in {*LAB_CLIENTS, "status-node"}:
            sys.exit(f"unknown lab device {service!r}")
    run([*LAB_COMPOSE, "exec", "-T", "--user", "10001", "-e", "DSN_LAB_CREDENTIALS=/tmp/lab/client.json",
         "-e", "DSN_LAB_CA=/tmp/lab/ca.crt", service, "python", "-m", "app.lab", *args])


@task
def demo_phase1() -> None:
    """Offline end-to-end intel demo: fixtures -> STIX 2.1 -> graph -> queries."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env["DSN_DEVICE_ID_HMAC_KEY"] = secrets.token_urlsafe(48)
    run(["uv", "run", "python", "-m", "app.cli", "demo-phase1"], cwd=BACKEND, env=env)


@task
def demo_phase2() -> None:
    """Offline devices + behavior demo: nmap fixture, simulated traffic and attacks."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env["DSN_DEVICE_ID_HMAC_KEY"] = secrets.token_urlsafe(48)
    run(["uv", "run", "python", "-m", "app.cli", "demo-phase2"], cwd=BACKEND, env=env)


@task
def demo_phase3() -> None:
    """Offline explainable-risk demo: intel + devices + attack -> scored, explained decisions."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env["DSN_DEVICE_ID_HMAC_KEY"] = secrets.token_urlsafe(48)
    run(["uv", "run", "python", "-m", "app.cli", "demo-phase3"], cwd=BACKEND, env=env)


@task
def demo_phase4() -> None:
    """Offline quarantine/recovery demo (dry-run driver, signed MQTT, audit chain)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env["DSN_DEVICE_ID_HMAC_KEY"] = secrets.token_urlsafe(48)
    run(["uv", "run", "python", "-m", "app.cli", "demo-phase4"], cwd=BACKEND, env=env)


@task
def demo_phase5() -> None:
    """Offline IoT demo: telemetry validation, signed commands + acks, broker-log rules."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env["DSN_DEVICE_ID_HMAC_KEY"] = secrets.token_urlsafe(48)
    run(["uv", "run", "python", "-m", "app.cli", "demo-phase5"], cwd=BACKEND, env=env)


@task
def evaluate() -> None:
    """Phase 7: seeded scenarios, threshold calibration, metrics -> docs/evaluation/phase7 (~25 min)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env["DSN_DEVICE_ID_HMAC_KEY"] = secrets.token_urlsafe(48)
    run(["uv", "run", "python", "-m", "app.cli", "evaluate"], cwd=BACKEND, env=env)


@task
def evaluate_report() -> None:
    """Rebuild the Phase 7 plots + summary from the saved CSV/JSON (no re-simulation)."""
    run(["uv", "run", "python", "-c", "from app.evaluation.report import regenerate; regenerate()"],
        cwd=BACKEND)


@task
def lab_eval() -> None:
    """Live end-to-end timings in the running virtual lab -> docs/evaluation/phase7/lab_runs.csv."""
    run(["uv", "run", "python", "../scripts/lab_eval.py", "--runs", os.environ.get("RUNS", "3")],
        cwd=BACKEND)


@task
def ablation() -> None:
    """Regenerate and execute docs/evaluation/ablation.ipynb (+ CSVs and plots)."""
    run(["uv", "run", "python", "../scripts/build_ablation_notebook.py"], cwd=BACKEND)


# --- Linux containers: for hosts that can't load spaCy's compiled extensions -------

DEV_IMAGE = "ghcr.io/astral-sh/uv:0.12.17-python3.13-trixie-slim"
NEO4J_IMAGE = "neo4j:5.26.31-community"
TEST_NET = "dsn-test"
TEST_NEO4J = "dsn-test-neo4j"
TEST_NEO4J_PASSWORD = "dsn-test-password"  # throwaway container, never published


def _docker_backend(command: str, extra_env: dict[str, str] | None = None) -> None:
    _require("docker")
    env_flags = [f"-e{k}={v}" for k, v in (extra_env or {}).items()]
    run(
        [
            "docker", "run", "--rm", "--network", TEST_NET,
            "-v", f"{ROOT}:/repo", "-v", "dsn-venv:/venv", "-v", "dsn-uv-cache:/root/.cache/uv",
            "-e", "UV_PROJECT_ENVIRONMENT=/venv", "-e", "UV_LINK_MODE=copy",
            *env_flags, "-w", "/repo/backend", DEV_IMAGE,
            "sh", "-c", f"uv sync --frozen --all-extras -q && {command}",
        ]
    )


def _start_test_neo4j() -> None:
    subprocess.run(["docker", "network", "create", TEST_NET], capture_output=True, check=False)
    subprocess.run(["docker", "rm", "-f", TEST_NEO4J], capture_output=True, check=False)
    run(
        [
            "docker", "run", "-d", "--name", TEST_NEO4J, "--network", TEST_NET,
            "-e", f"NEO4J_AUTH=neo4j/{TEST_NEO4J_PASSWORD}", NEO4J_IMAGE,
        ]
    )
    for _ in range(90):
        probe = subprocess.run(
            ["docker", "exec", TEST_NEO4J, "cypher-shell", "-u", "neo4j", "-p",
             TEST_NEO4J_PASSWORD, "RETURN 1"],
            capture_output=True, check=False,
        )
        if probe.returncode == 0:
            return
        time.sleep(2)
    sys.exit("neo4j did not become ready")


@task
def docker_test() -> None:
    """Full test suite on Linux with spaCy and a throwaway Neo4j (PYTEST_ARGS to narrow)."""
    _start_test_neo4j()
    args = os.environ.get("PYTEST_ARGS", "--cov --cov-report=term-missing")
    try:
        _docker_backend(
            f"uv run pytest {args}",
            {
                "DSN_TEST_NEO4J_URI": f"bolt://{TEST_NEO4J}:7687",
                "DSN_TEST_NEO4J_USER": "neo4j",
                "DSN_TEST_NEO4J_PASSWORD": TEST_NEO4J_PASSWORD,
            },
        )
    finally:
        subprocess.run(["docker", "rm", "-f", TEST_NEO4J], capture_output=True, check=False)


@task
def docker_test_nft() -> None:
    """Driver tests against real nftables/iptables (throwaway container, CAP_NET_ADMIN only)."""
    _require("docker")
    run(
        [
            "docker", "run", "--rm", "--cap-add", "NET_ADMIN",
            "-v", f"{ROOT}:/repo", "-v", "dsn-venv:/venv", "-v", "dsn-uv-cache:/root/.cache/uv",
            "-e", "UV_PROJECT_ENVIRONMENT=/venv", "-e", "UV_LINK_MODE=copy",
            "-e", "DSN_TEST_NFT=1", "-w", "/repo/backend", DEV_IMAGE,
            "sh", "-c",
            "apt-get update -qq >/dev/null && apt-get install -y -qq nftables >/dev/null && "
            "uv sync --frozen --all-extras -q && "
            "uv run pytest -q -p no:cacheprovider tests/test_response_drivers.py",
        ]
    )


TEST_MOSQUITTO = "dsn-test-mosquitto"


@task
def docker_test_mqtt() -> None:
    """Integration tests against a real TLS Mosquitto with provisioned creds + ACLs."""
    _require("docker")
    subprocess.run(["docker", "network", "create", TEST_NET], capture_output=True, check=False)
    subprocess.run(["docker", "rm", "-f", TEST_MOSQUITTO], capture_output=True, check=False)
    work = BACKEND / "data" / "mqtt-it"
    shutil.rmtree(work, ignore_errors=True)
    (work / "log").mkdir(parents=True)
    _docker_backend(
        "uv run python ../scripts/mqtt_provision.py --out data/mqtt-it --host mosquitto "
        "--device esp32-node --device rogue-sensor --no-device-files"
    )
    mosq = ROOT / "infra" / "mosquitto"
    run([
        "docker", "run", "-d", "--name", TEST_MOSQUITTO, "--network", TEST_NET,
        "--network-alias", "mosquitto",
        "--entrypoint", "/bin/sh",
        "-v", f"{mosq / 'config' / 'mosquitto.conf'}:/mosquitto/config/mosquitto.conf:ro",
        "-v", f"{mosq / 'entrypoint.sh'}:/entrypoint.sh:ro",
        "-v", f"{mosq / 'config' / 'acl'}:/mosquitto/src/acl:ro",
        "-v", f"{work / 'passwd'}:/mosquitto/src/passwd:ro",
        "-v", f"{work / 'certs'}:/mosquitto/src/certs:ro",
        "-v", f"{work / 'log'}:/mosquitto/log",
        "eclipse-mosquitto:2.0.22", "/entrypoint.sh",
    ])
    try:
        time.sleep(2)
        _docker_backend(
            "uv run pytest -q -p no:cacheprovider -p no:randomly tests/test_mqtt_integration.py",
            {
                "DSN_TEST_MQTT_DIR": "/repo/backend/data/mqtt-it",
                "DSN_TEST_MQTT_HOST": "mosquitto",
                "DSN_TEST_MQTT_LOG": "/repo/backend/data/mqtt-it/log/mosquitto.log",
            },
        )
    finally:
        subprocess.run(["docker", "logs", "--tail", "5", TEST_MOSQUITTO], check=False)
        subprocess.run(["docker", "rm", "-f", TEST_MOSQUITTO], capture_output=True, check=False)


@task
def docker_demo_phase1() -> None:
    """demo-phase1 inside a Linux container."""
    subprocess.run(["docker", "network", "create", TEST_NET], capture_output=True, check=False)
    _docker_backend(
        "uv run python -m app.cli demo-phase1",
        {"DSN_DEVICE_ID_HMAC_KEY": secrets.token_urlsafe(48)},
    )


@task
def docker_demo_phase2() -> None:
    """demo-phase2 inside a Linux container."""
    subprocess.run(["docker", "network", "create", TEST_NET], capture_output=True, check=False)
    _docker_backend(
        "uv run python -m app.cli demo-phase2",
        {"DSN_DEVICE_ID_HMAC_KEY": secrets.token_urlsafe(48)},
    )


@task
def gen_key() -> None:
    """Print a fresh value suitable for DSN_DEVICE_ID_HMAC_KEY."""
    print(secrets.token_urlsafe(48))


def _spawn(cmd: list[str], cwd: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    if os.name == "nt":
        return subprocess.Popen(
            cmd, cwd=cwd, env=env, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
    return subprocess.Popen(cmd, cwd=cwd, env=env, start_new_session=True)


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Stop a process and its children (uv and venv launchers spawn a child interpreter)."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"], check=False, capture_output=True
        )
    else:
        import signal

        os.killpg(proc.pid, signal.SIGTERM)
    proc.wait(timeout=10)


def _get(url: str) -> tuple[int, object]:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 - fixed localhost URL
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as err:
        return err.code, json.load(err)


@task
def demo_phase0() -> None:
    """Boot the API offline, query health endpoints, then shut down."""
    port = "8765"
    env = {k: v for k, v in os.environ.items() if not k.startswith("DSN_")}
    env |= {
        "DSN_API_PORT": port,
        "DSN_LOG_JSON": "true",
        # Ephemeral key: the demo never persists device IDs.
        "DSN_DEVICE_ID_HMAC_KEY": secrets.token_urlsafe(48),
    }
    print(f"starting backend on 127.0.0.1:{port} (DRY_RUN, offline, ephemeral HMAC key)")
    proc = _spawn(["uv", "run", "python", "-m", "app"], BACKEND, env)
    try:
        base = f"http://127.0.0.1:{port}"
        # Startup trains the Isolation Forest and XGBoost models (and, on a fresh
        # machine, builds matplotlib's font cache): ~14 s on a CI runner.
        for _ in range(240):
            try:
                _get(f"{base}/api/health")
                break
            except (urllib.error.URLError, ConnectionError):
                if proc.poll() is not None:
                    sys.exit("backend exited during startup")
                time.sleep(0.25)
        else:
            sys.exit("backend did not become healthy in 60s")
        for path in ("/api/health", "/api/health/ready"):
            status, body = _get(base + path)
            print(f"\nGET {path} -> {status}\n{json.dumps(body, indent=2)}")
        print("\nPhase 0 demo OK")
    finally:
        _kill_tree(proc)


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in TASKS:
        print("tasks:")
        for name, fn in TASKS.items():
            print(f"  {name:<14} {(fn.__doc__ or '').strip()}")
        sys.exit(0 if len(sys.argv) == 1 else 2)
    try:
        TASKS[sys.argv[1]]()
    except subprocess.CalledProcessError as err:
        sys.exit(err.returncode)


if __name__ == "__main__":
    main()
