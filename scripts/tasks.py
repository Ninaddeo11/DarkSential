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


@task
def setup() -> None:
    """Install backend and frontend dependencies."""
    _require("uv")
    run(["uv", "sync", "--frozen", "--all-extras"], cwd=BACKEND)
    run([NPM, "ci"], cwd=FRONTEND)
    env_file = ROOT / ".env"
    if not env_file.exists():
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        text = text.replace("DSN_DEVICE_ID_HMAC_KEY=\n", f"DSN_DEVICE_ID_HMAC_KEY={secrets.token_urlsafe(48)}\n")
        text = text.replace("change-me-to-a-long-random-password", secrets.token_urlsafe(24))
        env_file.write_text(text, encoding="utf-8")
        print("created .env with freshly generated secrets")


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
    test()
    run([NPM, "run", "build"], cwd=FRONTEND)


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
        for _ in range(60):
            try:
                _get(f"{base}/api/health")
                break
            except (urllib.error.URLError, ConnectionError):
                if proc.poll() is not None:
                    sys.exit("backend exited during startup")
                time.sleep(0.25)
        else:
            sys.exit("backend did not become healthy in 15s")
        for path in ("/api/health", "/api/health/ready"):
            status, body = _get(base + path)
            print(f"\nGET {path} -> {status}\n{json.dumps(body, indent=2)}")
        print("\nPhase 0 demo OK")
    finally:
        _kill_tree(proc)


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in TASKS:
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
