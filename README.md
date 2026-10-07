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
| 1 | Threat-intel feeds → STIX 2.1 → Neo4j, NLP | ✅ done |
| 2 | Device discovery and behavior baselines | ✅ done |
| 3 | Explainable risk engine | ✅ done |
| 4 | Quarantine and recovery | ✅ done |
| 5 | Mosquitto TLS/ACL and ESP32 firmware | ✅ done |
| 6 | Real-time API and 3D command center | ⏳ |
| 7 | Simulation and evaluation | ⏳ |

## Quick start

Requirements: Python ≥ 3.11, [uv](https://docs.astral.sh/uv/) 0.12+, Node 24, and
(optionally) Docker.

```bash
make setup          # install deps (incl. the `lab` extra); creates .env with generated secrets
make demo-phase0    # boot the API offline, print health/readiness, shut down
make demo-phase1    # offline intel demo: 7 feeds -> STIX 2.1 -> graph -> queries + NLP
make demo-phase2    # devices + behavior: nmap fixture, simulated traffic + attacks -> detections
make demo-phase3    # explainable risk: scored decisions, contributions, evidence paths, SHAP
make demo-phase4    # quarantine/recovery: refusal, auto-quarantine, reconcile, audit chain
make demo-phase5    # IoT: telemetry validation, signed commands + acks, broker-log rules
make ablation       # re-run the executed ablation notebook (docs/evaluation/)
make check          # ruff + mypy --strict + pytest (80% gate) + frontend build
make docker-test    # full suite on Linux with spaCy + a throwaway Neo4j (needs Docker)
```

Windows without `make`: use `python scripts/tasks.py <task>`, for example
`python scripts/tasks.py demo-phase0`. Run `python scripts/tasks.py` to list tasks.

> **Windows Smart App Control / Application Control** can block spaCy's compiled
> extensions. NLP tests then skip locally, and `demo-phase1` finishes without the
> NLP step. Use `make docker-test` / `make docker-demo-phase1` to run the full
> suite and demo on Linux. CI always runs everything.

### Threat intel (Phase 1)

Feeds run on a persistent schedule (`backend/config/feeds.yaml`). Offline mode
(the default) replays `/fixtures` through the real parsers. For live mode, set
`DSN_OFFLINE_MODE=false` and the keys you have:

| Feed | Needs |
|---|---|
| CISA KEV, MITRE ATT&CK, Feodo Tracker | nothing |
| NVD | optional `DSN_NVD_API_KEY` (raises the rate limit) |
| URLhaus, ThreatFox | `DSN_ABUSECH_AUTH_KEY` (free at auth.abuse.ch) |
| Dark-web provider | `DSN_DARKWEB_API_URL`, `DSN_DARKWEB_API_KEY`, plus the field mapping (`DSN_DARKWEB_*`) |

Feeds whose key is missing are reported as `missing_credentials` and skipped.

```bash
cd backend
uv run python -m app.cli ingest                 # run all enabled feeds now
uv run python -m app.cli related 162.243.103.246
uv run python -m app.cli cves "cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.1:*:*:*:*:*:*:*"
uv run python -m app.cli extract "C2 at evil[.]example[.]com, CVE-2023-1389, T1190"
```

Read-only API (lab mode): `GET /api/feeds/status`,
`GET /api/intel/related-threats?ioc=`, `GET /api/intel/cves?cpe=`,
`GET /api/intel/techniques?rule_id=`, `GET /api/intel/graph/counts`,
`POST /api/intel/extract`. Without `DSN_NEO4J_URI` the graph is in-memory and is
lost on restart. With `make up`, Neo4j is wired in automatically.

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
deployment (`make up`). Use Vercel for the dashboard. In hosted mode
`/api/feeds/status` shows configuration only, and `/api/intel/*` returns 503,
because there is no graph there.

`requirements.txt` at the root is generated from `backend/uv.lock`
(`make export-reqs`), and CI fails if the two drift apart.

### Devices & behavior (Phase 2)

Devices are discovered by nmap, by passive ARP/DHCP/mDNS listening, and from
BLE advertisements. Each is keyed by `HMAC(key, MAC)`, gets an OUI vendor and
CPE guesses, and has a trust state (`unknown` → `known` after 24 h, or
`approved`). Traffic is scored per device per minute: Welford baselines (log
scale) plus a signed Isolation Forest, and YAML rules mapped to ATT&CK.

Every discovery source is **off by default** and capability-checked. Active nmap
scans and Wi-Fi monitoring also need `DSN_DRY_RUN=false` (see
`GET /api/discovery/capabilities`).

```bash
cd backend
uv run python -m app.cli scan --profile service          # DRY_RUN: prints the plan
uv run python -m app.cli discover-xml ../fixtures/events/lab-scan.nmap.xml
uv run python -m app.cli replay capture.pcap               # or a .jsonl of TrafficEvents
uv run python -m app.cli devices
uv run python -m app.cli approve dev-0123456789abcdef
```

Read-only API: `GET /api/devices`, `/api/devices/{node_id}`, `/api/detections`,
`/api/events`, `/api/rules`, `/api/discovery/capabilities`.

### Explainable risk (Phase 3)

Every device gets a score from a transparent linear model
(`backend/config/risk.yaml`, weights sum to 1), built from five factors: unknown
device, rate anomaly, protocol anomaly, threat-intel correlation and vulnerable
service. Each decision stores every factor's value, weight and contribution
(they sum to the score), a plain-English explanation, the recommended action and
the graph evidence paths. An XGBoost model with SHAP explanations is attached for
comparison and never changes the decision. See the
[ablation notebook](docs/evaluation/ablation.ipynb).

```bash
cd backend && uv run python -m app.cli risk dev-0123456789abcdef
```

Read-only API: `GET /api/risk` (all devices, highest first), `/api/risk/{node_id}`
(latest + history), `/api/risk/model` (weights, thresholds, SHAP importances).

### Quarantine & recovery (Phase 4)

CRITICAL risk triggers an automatic, time-limited quarantine. Manual quarantine,
release and approval go through the API (bearer `DSN_ADMIN_TOKEN`) or the CLI.
Every action lands in a hash-chained audit log. Protected hosts are never
quarantined, and with `DSN_DRY_RUN=true` (the default) the firewall is never
touched; you just see the exact nft commands.

```bash
cd backend
uv run python -m app.cli quarantine dev-0123456789abcdef 30
uv run python -m app.cli release dev-0123456789abcdef
uv run python -m app.cli audit --verify
curl -X POST localhost:8000/api/quarantines -H "Authorization: Bearer $DSN_ADMIN_TOKEN" \
     -H 'Content-Type: application/json' -d '{"node_id":"dev-…","reason":"manual","minutes":30}'
```

**Real enforcement** runs on the lab gateway only, after testing in dry-run:
set `DSN_DRY_RUN=false` and `DSN_PROTECTED_HOSTS`, then
`docker compose --env-file .env -f infra/docker-compose.yml -f infra/docker-compose.gateway.yml up -d`
(host network, `NET_ADMIN`/`NET_RAW` only, nftables driver). Read the warnings
in that file first.

### IoT layer: broker and ESP32 (Phase 5)

The Mosquitto broker (`infra/mosquitto/`) is set up as follows:

- **Transport.** It accepts **TLS only**, on port 8883, using a lab CA with EC P-256 keys.
- **Accounts.** Every client has its own password, stored as a PBKDF2-SHA512 hash. Anonymous access is off.
- **Topic access.** ACLs are deny-by-default: a device can publish only to `dsn/telemetry/<its own user>`.
- **Limits.** `mosquitto.conf` caps connection count, packet size, keepalive, and in-flight and queued messages. Mosquitto has no per-client message-rate limit, so message floods are detected (`mqtt_connect_flood`) rather than throttled. A host-level new-connection rate limit is in `broker-ratelimit.nft`.

`make setup` provisions everything the broker and the backend need:

- the CA and server certificate
- the `passwd` file
- the backend's MQTT password and command key, written into `.env`
- one serial provisioning file per ESP32 (gitignored)

To add devices, run `python scripts/mqtt_provision.py --device <name> --host <broker-ip>`.

The backend:

- **Consumes telemetry.** Payloads are validated (size, schema, charset) before they reach the device registry.
- **Tails the broker log.** CONNECT, authentication failures, wildcard subscriptions and ACL-denied publishes become behavior events. This is how the `mqtt_wildcard_subscription` and `mqtt_restricted_publish` rules fire on real traffic.
- **Signs the commands it sends** to the status node with HMAC.

The [ESP32 firmware](firmware/esp32-node/README.md) does the following:

- Shows NORMAL, ALERT and QUARANTINED on an RGB LED.
- Publishes telemetry.
- Verifies each command's signature, freshness and replay status before acting, then acks it.
- Reconnects with jittered backoff.
- Reads its credentials from NVS. They are entered over serial and never compiled in.

That README covers wiring, flashing and provisioning.

```bash
make docker-test-mqtt   # integration tests against a real TLS Mosquitto (Docker)
make firmware-test      # firmware unit tests on the host + esp32dev/esp32dev_ble builds (Docker)
```

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
