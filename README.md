# Darknet Sentinel Nexus

A defensive, explainable IoT security platform for a lab network **you own**. It
ingests threat intelligence (including licensed dark-web-sourced feeds), profiles
IoT devices, scores risk with explainable models, can quarantine devices, and
streams everything to a real-time 3D command center.

> **Safety defaults:** `DSN_DRY_RUN=true` (no enforcing action touches the network)
> and `DSN_OFFLINE_MODE=true` (feeds replay `/fixtures`). No offensive tooling,
> no exploit code, no Tor crawler.

![The command center during a lab scenario: the smart plug is quarantined (magenta,
pulsing), its risk waterfall and SHAP comparison are open on the right, and the timeline
shows the events as they streamed in](docs/img/command-center.png)

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffold, config, logging, health, CI, architecture and threat model | ✅ done |
| 1 | Threat-intel feeds → STIX 2.1 → Neo4j, NLP | ✅ done |
| 2 | Device discovery and behavior baselines | ✅ done |
| 3 | Explainable risk engine | ✅ done |
| 4 | Quarantine and recovery | ✅ done |
| 5 | Mosquitto TLS/ACL and the virtual IoT lab | ✅ done |
| 6 | Real-time API and 3D command center | ✅ done |
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
make lab-up         # the virtual IoT lab (Docker): devices, gateway, real nftables quarantine
                    # then open http://127.0.0.1:5173 for the 3D command center
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
2. Add the environment variables `DSN_DEVICE_ID_HMAC_KEY`, `DSN_AUTH_JWT_SECRET`
   and `DSN_VIEWER_TOKEN` (each `make gen-key`). Hosted mode runs as production,
   where every read requires a session: sign in with the viewer token.
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

### Virtual lab: no hardware needed (Phase 5)

The whole platform runs in software. `make lab-up` starts a sandboxed IoT network in Docker:

| Lab client | What it is |
|---|---|
| `cam-front` | IP camera (Hikvision MAC prefix), modern web server |
| `cam-yard` | IP camera whose web server answers as **GoAhead 3.6.4**, a version with CVE-2017-17562 on CISA's known-exploited list (a banner only, no vulnerable code) |
| `thermo-hall`, `plug-lab`, `sensor-gate` | thermostat, smart plug and air sensor |
| `status-node` | the virtual status node: verifies HMAC-signed commands and shows NORMAL / ALERT / QUARANTINED in its telemetry |
| `rogue-sensor` | an unapproved device with a randomized MAC, started on demand |

Every device's traffic is routed through the **backend container, which acts as the lab gateway**:

- **Discovery.** It scans the device range with nmap and identifies vendors from MAC addresses.
- **Capture.** It captures each device's connections into the behavior pipeline.
- **Enforcement.** It quarantines with **real nftables rules**, confined to its own network namespace. A quarantined device is genuinely cut off from the broker.
- **Egress lock.** Only device ↔ broker traffic is forwarded. Anything else, such as a beacon to a known C2 address, is recorded and dropped. Nothing leaves the sandbox.

```bash
make lab-up                          # provision, start, load threat intel
make lab-status                      # containers + what the backend knows per device
python scripts/tasks.py lab-attack flood            # plug-lab: 500 MQTT connects/min for 2 min
python scripts/tasks.py lab-attack c2 [device]      # beacon to a Feodo-listed C2 IP (dropped)
python scripts/tasks.py lab-attack wildcard         # subscribe to '#' and the command topics
python scripts/tasks.py lab-attack restricted       # publish to topics the ACL forbids
python scripts/tasks.py lab-attack bad-auth         # wrong-password logins
python scripts/tasks.py lab-attack rogue            # an unknown device joins
make lab-down
```

If port 8000 is taken, set `DSN_BACKEND_HOST_PORT` (e.g. `8010`) before `lab-up`; the lab tasks use it too.

The broker (`infra/mosquitto/`):

- **Transport.** TLS only, on port 8883, using a lab CA with EC P-256 keys.
- **Accounts.** Every client has its own password, stored as a PBKDF2-SHA512 hash. Anonymous access is off. `make setup` / `lab-up` write one credentials file per lab client (`infra/lab/secrets/`, gitignored).
- **Topic access.** ACLs are deny-by-default: a device can publish only to `dsn/telemetry/<its own user>` and `home/<its own user>/#`.
- **Limits.** `mosquitto.conf` caps connection count, packet size, keepalive, and in-flight and queued messages. Mosquitto has no per-client message-rate limit, so floods are detected (`mqtt_connect_flood`) rather than throttled. A host-level new-connection rate limit is in `broker-ratelimit.nft`.

The backend also tails the broker log: CONNECT, authentication failures, wildcard subscriptions and ACL-denied publishes become behavior events.

```bash
make docker-test-mqtt   # integration tests against a real TLS Mosquitto (Docker)
```

### Command center (Phase 6)

With the stack or the virtual lab running, open <http://127.0.0.1:5173>:

- **3D network.** Devices around the DSN gateway. Colour = risk level (magenta =
  quarantined), size = score, a pulse marks new activity. Drag to orbit; click a
  device (or pick it in the ranked list) to inspect it.
- **Inspector.** Identity and services; the risk score as a **waterfall** of factor
  contributions; the XGBoost **SHAP** comparison; the **threat-graph** path (e.g.
  device → GoAhead 3.6.4 → CVE-2017-17562); and, for operators, **quarantine /
  release / approve** with a required, audited reason.
- **Event timeline** (live, filterable) and **feed health**.

Events stream over Socket.IO (`/api/socket.io`). They are batched every 100 ms,
resumed from the last seen event after a reconnect, and typed by a schema
generated from the backend (`make gen-types`; CI checks it is current).

**Sign in** (top right) with the operator secret `DSN_ADMIN_TOKEN` or the read-only
`DSN_VIEWER_TOKEN` (`make setup` generates both into `.env`). The secret is exchanged
once for a 60-minute session token. Alternatively configure OIDC
(`DSN_OIDC_ISSUER`, `DSN_OIDC_AUDIENCE`, `DSN_OIDC_JWKS_URL`): tokens carrying the
`dsn-operator` role are operators. In production every read needs a token. Rate
limits: logins 10/min, mutations 30/min, reads 600/min per client.

```bash
cd frontend && npm test     # store, layout, waterfall unit tests
make dev-frontend           # Vite dev server; DSN_API_PROXY=http://127.0.0.1:8010 for the lab
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
backend/app/{api,core,feeds,intel,graph,detect,behavior,risk,response,mqtt,lab,simulation,models}
backend/tests   fixtures/   frontend/   infra/ (lab/, mosquitto/)   docs/   scripts/
```

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Changelog](CHANGELOG.md)
