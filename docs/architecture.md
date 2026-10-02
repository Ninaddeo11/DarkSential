# Architecture

Darknet Sentinel Nexus (DSN) is a **defensive** platform for a single lab network
the operator owns. It correlates threat intelligence with observed IoT device
behavior, produces explainable risk decisions, and can quarantine devices,
behind a dry-run switch that is **on by default**.

Status markers: ✅ implemented · ⏳ planned (phase noted).

## Component view

```
                 ┌──────────────────────── Internet (untrusted) ────────────────────────┐
                 │ CISA KEV · NVD · MITRE ATT&CK · abuse.ch · licensed dark-web intel   │
                 └───────────────┬──────────────────────────────────────────────────────┘
                                 │ HTTPS, rate-limited, cached        (offline: /fixtures)
┌────────────────────────────────▼───────────────────────────────────────────────────────┐
│ backend (FastAPI)                                                                      │
│                                                                                        │
│  feeds/ ⏳P1 ──► intel/ (NLP) ⏳P1 ──► graph/ (STIX 2.1 → Neo4j) ⏳P1                  │
│                                              ▲                                         │
│  detect/ ⏳P2 ──► behavior/ ⏳P2 ──► risk/ ⏳P3 ──► response/ ⏳P4 ──► nftables/DRY-RUN  │
│     ▲   (nmap, ARP/DHCP/mDNS, BLE)     │ explanations                 │                 │
│     │                                  ▼                              ▼                 │
│  mqtt/ ⏳P4-5 ◄──── telemetry ──── api/ + Socket.IO ⏳P6       audit log (DB)           │
│                                                                                        │
│  core/ ✅ config · logging/redaction · HMAC device IDs · health registry               │
└───────┬───────────────────┬────────────────────────┬───────────────────────────────────┘
        │ MQTT/TLS          │ Bolt                   │ HTTP/WS
┌───────▼──────┐    ┌───────▼──────┐        ┌────────▼─────────┐
│ Mosquitto    │    │ Neo4j        │        │ frontend (React, │
│ (ACLs, TLS)  │    │ STIX graph   │        │ 3D command center)│
└───────▲──────┘    └──────────────┘        └──────────────────┘
        │ MQTT/TLS
┌───────┴──────┐
│ ESP32 status │  RGB LED: NORMAL / ALERT / QUARANTINED   ⏳P5
│ node         │
└──────────────┘
```

## Data flow (target)

1. **Ingest:** each `FeedAdapter` fetches (or replays fixtures), normalizes to
   validated STIX 2.1 and upserts into Neo4j with provenance (source,
   first_seen, last_seen, confidence). Free text goes through the NLP pipeline
   as *data only*.
2. **Observe:** discovery and passive sensors build the device registry. Devices
   are keyed by `HMAC-SHA256(key, MAC)`.
3. **Profile:** sliding-window features feed Welford baselines and an Isolation
   Forest. YAML rules map behaviors to ATT&CK techniques.
4. **Score:** a linear, config-weighted scorer produces score, level and
   per-factor contributions. An XGBoost/SHAP model runs alongside it for
   comparison. Every decision stores its explanation and evidence path.
5. **Respond:** the `ResponseDriver` applies quarantine (nftables/iptables), or
   only logs it under DRY_RUN. Protected hosts are never quarantined. Recovery is
   scheduled persistently, and everything is audited.
6. **Show:** typed Socket.IO events drive the dashboard.

## Phase 0 components

| Module | Responsibility |
|---|---|
| `app/core/config.py` | Typed `Settings` (prefix `DSN_`). Fails fast on an HMAC key shorter than 32 bytes, wildcard/path CORS origins, a non-private `lab_cidr`, half-configured credentials, or http CORS in production. `DRY_RUN` and `OFFLINE_MODE` default to `true`. |
| `app/core/logging.py` | JSON (or plain) logs. Masks secret-looking keys and any configured secret value, and escapes control characters in plain mode (log injection). |
| `app/core/identifiers.py` | MAC normalization, OUI extraction, keyed device IDs, constant-time matching. |
| `app/core/health.py` | Registry of async dependency checks with a timeout. Errors expose only the exception type. |
| `app/api/health.py` | `GET /api/health` (liveness), `GET /api/health/ready` (readiness, 503 if any check errors). |
| `app/main.py` | App factory (no import-time side effects): CORS allowlist, security headers, validated `X-Request-ID`, OpenAPI disabled in production. |

## Key design decisions

- **App factory, no global app.** Tests build isolated apps from explicit
  `Settings`, and importing modules needs no secrets.
- **Dependencies land with the phase that uses them.** Each phase's lockfile
  diff then shows exactly what it introduced.
- **Readiness is honest.** Subsystems that don't exist yet report
  `not_configured` instead of `ok`.
- **Guardrails live in config validation.** A non-private `lab_cidr` is
  rejected at startup, so later scanning or enforcement code cannot be pointed
  at someone else's network through a typo.
- **Cross-platform tasks.** `scripts/tasks.py` (stdlib only) is the source of
  truth and `make` delegates to it.

## Deployment

There are two deployment modes (`DSN_DEPLOYMENT`):

| | `lab` (docker-compose) | `hosted` (Vercel) |
|---|---|---|
| Frontend | nginx container | Vercel static (`frontend/dist`) |
| API | long-running uvicorn | Python serverless function (`api/index.py`) |
| Enforcement | allowed when `DRY_RUN=false` | **rejected at startup**: dry-run only |
| Discovery / MQTT / scheduler | yes (later phases) | no (no LAN access, no long-lived processes) |
| Intended use | full platform | dashboard and read-only intel views |

The Vercel entrypoint *forces* `hosted` (it overwrites any configured value), and
settings validation makes `hosted` combined with `DRY_RUN=false` a startup error.
Later phases must keep stateful subsystems (scheduler, MQTT consumer, response
drivers) out of the hosted import path, or gate them on `deployment == "lab"`.

### Lab stack

`infra/docker-compose.yml` runs Mosquitto, Neo4j, the backend and the frontend
(nginx) on a private bridge network. Published ports bind to `127.0.0.1` only.
Backend and frontend containers run as non-root with all capabilities dropped,
and the backend's root filesystem is read-only. Phase 4 will need `NET_ADMIN`
for nftables, granted to a dedicated, separate enforcement container rather
than the API.
