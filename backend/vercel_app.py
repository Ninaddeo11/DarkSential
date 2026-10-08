"""Vercel entrypoint for the `backend` service (vercel.json: entrypoint "vercel_app:app").

The service root is backend/, and Vercel passes the original request path, so the
app keeps serving its routes under /api exactly as in the lab deployment.

Hosted mode is FORCED here, not defaulted: a cloud function cannot reach the lab
network, so it must never be able to enforce. Settings validation rejects
DSN_DRY_RUN=false in hosted mode, and the function fails to start.

Required Vercel env var: DSN_DEVICE_ID_HMAC_KEY (>= 32 bytes).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The service root (this directory) holds the `app` package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ["DSN_DEPLOYMENT"] = "hosted"
os.environ.setdefault("DSN_ENV", "production")
os.environ.setdefault("DSN_LOG_JSON", "true")
# Frontend and API share an origin on Vercel; allow the production domain for
# any cross-origin tooling. Override with DSN_CORS_ORIGINS if needed.
_production_host = os.environ.get("VERCEL_PROJECT_PRODUCTION_URL")
if _production_host:
    os.environ.setdefault("DSN_CORS_ORIGINS", f"https://{_production_host}")

from app.main import create_app  # noqa: E402

app = create_app()
