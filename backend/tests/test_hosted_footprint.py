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

    BLOCKED = {"spacy", "neo4j", "stix2", "stix2patterns", "apscheduler", "sqlalchemy"}

    class Blocker(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in BLOCKED:
                raise ImportError(f"lab dependency imported in hosted mode: {name}")
            return None

    sys.meta_path.insert(0, Blocker())
    os.environ["DSN_DEVICE_ID_HMAC_KEY"] = sys.argv[1]
    os.environ["VERCEL_PROJECT_PRODUCTION_URL"] = "dsn.vercel.app"

    spec = importlib.util.spec_from_file_location("vercel_index", sys.argv[2])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from fastapi.testclient import TestClient

    with TestClient(module.app) as client:
        assert client.get("/api/health").json()["deployment"] == "hosted"
        assert client.get("/api/health/ready").status_code == 200
        assert client.get("/api/feeds/status").json()["scheduler"] == "unavailable_hosted"
        cpe = "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"
        assert client.get("/api/intel/cves", params={"cpe": cpe}).status_code == 503
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
