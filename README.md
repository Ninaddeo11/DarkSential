# Darknet Sentinel Nexus

A defensive, explainable IoT security platform for a lab network **you own**. It
ingests threat intelligence (including licensed dark-web-sourced feeds), profiles
IoT devices, scores risk with explainable models, can quarantine devices, and
streams everything to a real-time 3D command center.

> **Safety defaults:** `DSN_DRY_RUN=true` (no enforcing action touches the network)
> and `DSN_OFFLINE_MODE=true` (feeds replay `/fixtures`). No offensive tooling,
> no exploit code, no Tor crawler.

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffold, config, logging, health, CI, architecture and threat model | ✅ done |
| 1 | Threat-intel feeds → STIX 2.1 → Neo4j, NLP | ⏳ |
| 2 | Device discovery and behavior baselines | ⏳ |
| 3 | Explainable risk engine | ⏳ |
| 4 | Quarantine and recovery | ⏳ |
| 5 | Mosquitto TLS/ACL and ESP32 firmware | ⏳ |
| 6 | Real-time API and 3D command center | ⏳ |
| 7 | Simulation and evaluation | ⏳ |

## Quick start

Requirements: Python ≥ 3.11, [uv](https://docs.astral.sh/uv/) 0.12+, Node 24, and
(optionally) Docker.

```bash
make setup          # install deps; creates .env with generated secrets if missing
make demo-phase0    # boot the API offline, print health/readiness, shut down
make check          # ruff + mypy --strict + pytest (80% gate) + frontend build
```

Windows without `make`: use `python scripts/tasks.py <task>`, for example
`python scripts/tasks.py demo-phase0`. Run `python scripts/tasks.py` to list tasks.

### Local development

```bash
make dev-backend    # http://127.0.0.1:8000  (OpenAPI at /docs outside production)
make dev-frontend   # http://127.0.0.1:5173  (proxies /api to the backend)
```

### Full stack (Docker)

```bash
make setup          # ensures .env exists
make up             # mosquitto, neo4j, backend, frontend (all bound to 127.0.0.1)
make down
```

### Deploy to Vercel (hosted mode)

The repo root is a ready Vercel project: the frontend is served statically from
`frontend/dist`, and the FastAPI app runs as a Python function at `/api/*`
([api/index.py](api/index.py), [vercel.json](vercel.json)).

1. Import the GitHub repo in Vercel. Keep the root directory at the repo root;
   the build settings come from `vercel.json`.
2. Add the environment variable `DSN_DEVICE_ID_HMAC_KEY` (`make gen-key`). It is
   the only required one.
3. Deploy, then check `https://<project>.vercel.app/api/health`.

Hosted mode is **forced** by the entrypoint and is dry-run only:
`DSN_DRY_RUN=false` makes the function refuse to start. A cloud function can't
reach your lab network, hold MQTT connections, run nftables or keep persistent
schedulers, so enforcement, discovery and the broker stay on the lab
deployment (`make up`). Use Vercel for the dashboard and read-only intel views.

`requirements.txt` at the root is generated from `backend/uv.lock`
(`make export-reqs`), and CI fails if the two drift apart.

## Configuration

All settings come from environment variables prefixed `DSN_` (see
[.env.example](.env.example)). The app refuses to start when:

- `DSN_DEVICE_ID_HMAC_KEY` is missing or shorter than 32 bytes (`make gen-key`)
- a CORS origin is a wildcard, has a path, or is not http(s) (https only in production)
- `DSN_LAB_CIDR` is not a private, non-loopback network
- a credential pair is half-configured (e.g. Neo4j URI without password)

## Layout

```
backend/app/{api,core,feeds,intel,graph,detect,behavior,risk,response,mqtt,simulation,models}
backend/tests   fixtures/   frontend/   firmware/esp32-node/   infra/   docs/   scripts/
```

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Changelog](CHANGELOG.md)
