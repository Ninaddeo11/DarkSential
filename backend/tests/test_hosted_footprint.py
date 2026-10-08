"""The hosted (Vercel) app must not import the `lab` extra.

Runs in a subprocess that makes the lab packages unimportable, then exercises
the hosted entrypoint. If any lab-only import leaks into the hosted path, the
app fails to build here.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

from tests.conftest import TEST_HMAC_KEY

SCRIPT = textwrap.dedent(
    """
    import importlib.abc, importlib.util, os, sys

    BLOCKED = {
        "spacy", "neo4j", "stix2", "stix2patterns", "apscheduler", "sqlalchemy", "socketio",
    }

    class Blocker(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in BLOCKED:
                raise ImportError(f"lab dependency imported in hosted mode: {name}")
            return None

    sys.meta_path.insert(0, Blocker())
    os.environ["DSN_DEVICE_ID_HMAC_KEY"] = sys.argv[1]
    os.environ["VERCEL_PROJECT_PRODUCTION_URL"] = "dsn.vercel.app"
    os.environ["DSN_AUTH_JWT_SECRET"] = "hosted-jwt-secret-0123456789abcdef"
    os.environ["DSN_VIEWER_TOKEN"] = "hosted-viewer-token-0123456789abcd"

    spec = importlib.util.spec_from_file_location("vercel_index", sys.argv[2])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from fastapi.testclient import TestClient

    with TestClient(module.app) as client:
        assert client.get("/api/health").json()["deployment"] == "hosted"
        assert client.get("/api/health/ready").status_code == 200
        # Internet-facing production: reads need a session, and there is no live socket.
        assert client.get("/api/feeds/status").status_code == 401
        sio = {"EIO": "4", "transport": "polling"}
        assert client.get("/api/socket.io/", params=sio).status_code == 404
        secret = os.environ["DSN_VIEWER_TOKEN"]
        login = client.post("/api/auth/login", json={"secret": secret})
        assert login.json()["role"] == "viewer"
        auth = {"Authorization": "Bearer " + login.json()["access_token"]}
        status = client.get("/api/feeds/status", headers=auth).json()
        assert status["scheduler"] == "unavailable_hosted"
        cpe = "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"
        assert client.get("/api/intel/cves", params={"cpe": cpe}, headers=auth).status_code == 503
        mutate = {"node_id": "dev-0000000000000000", "reason": "abc"}
        assert client.post("/api/quarantines", json=mutate, headers=auth).status_code == 403
    leaked = sorted(m for m in sys.modules if m.split(".")[0] in BLOCKED)
    assert not leaked, leaked
    print("HOSTED_OK")
    """
)


def test_hosted_app_runs_without_lab_dependencies() -> None:
    from tests.test_vercel_entrypoint import ENTRYPOINT

    proc = subprocess.run(
        [sys.executable, "-c", SCRIPT, TEST_HMAC_KEY, str(ENTRYPOINT)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={k: v for k, v in __import__("os").environ.items() if not k.startswith("DSN_")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "HOSTED_OK" in proc.stdout
