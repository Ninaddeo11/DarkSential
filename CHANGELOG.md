# Changelog

## [0.6.0] Phase 5: IoT layer (Mosquitto + ESP32), 2026-10-08

### Added
- **Mosquitto hardening:**
  - TLS-only listener on 8883 with a lab CA (EC P-256)
  - `$7$` PBKDF2-SHA512 per-client passwords; no anonymous access
  - deny-by-default topic ACLs using `%u` patterns
  - connection, packet and queue caps
  - an entrypoint that installs the secrets as `mosquitto:0600`
  - `broker-ratelimit.nft`, a new-connection rate meter
- `scripts/mqtt_provision.py`. It generates:
  - the CA and server certificate
  - the `passwd` file
  - `credentials.json` (the users and the command key)
  - a serial provisioning file per ESP32

  `make setup` runs it and writes the backend's MQTT password and command key into `.env`.
- Backend `TelemetryConsumer`: validated telemetry goes to the device registry, and becomes traffic events when there is no broker log.
- Backend `BrokerLogParser` / `BrokerLogTailer`: CONNECT, authentication failures, SUBSCRIBE and denied PUBLISH become behavior events. Service clients are ignored.
- **ESP32 firmware** (`firmware/esp32-node`, PlatformIO):
  - MQTT over TLS
  - RGB LED states (BOOT, PROVISION, OFFLINE, NORMAL, ALERT, QUARANTINED)
  - telemetry every 10 s
  - HMAC command verification with staleness and replay checks, plus acks
  - reconnect with jittered backoff
  - NVS-backed serial provisioning
  - an optional read-only BLE GATT service

  18 host unit tests cover the portable core.
- Tasks:
  - `demo-phase5`
  - `docker-test-mqtt` (a real TLS broker)
  - `firmware-test` (native tests and both device builds, in Docker)
- CI jobs `iot` (a real Mosquitto) and `firmware` (`pio test -e native` and both builds). The demo job runs `demo-phase5`.

### Fixed / found during this phase
- The broker logged permission warnings for world-readable `passwd`/`acl` files on bind mounts. The entrypoint now copies them with the correct ownership and mode.
- The backend's own wildcard subscription and command publishes tripped the `mqtt_wildcard_subscription` and `mqtt_restricted_publish` rules. Service clients are now excluded from the broker-log parser.
- The BLE firmware build exceeded the default 1.25 MB app partition. The `esp32dev_ble` env now uses `huge_app.csv`.

### Known limitations
- The firmware is compiled and its logic is host-tested, but it has not been run on physical hardware here.
- Devices authenticate with passwords, not mutual TLS.
- The replay cache does not survive a reboot.
- Behind NAT, the broker log attributes all clients to the NAT address.
- Mosquitto has no per-client message-rate limit, so message floods are detected rather than throttled.

### Unverified assumptions
- The broker log line formats were captured from mosquitto 2.0.22 only. Other versions may differ; the parser skips lines it does not recognise.

## [0.5.0] Phase 4: Response (quarantine & recovery), 2026-10-07

### Added
- `ResponseDriver` with `NftablesDriver` (own `inet dsn` table, v4/v6 sets,
  atomic element ops, atomic table replace), `IptablesDriver` (own chain,
  idempotent) and `DryRunDriver` (records planned commands). DRY_RUN forces
  dry-run. An unavailable driver falls back to dry-run and readiness reports
  the error.
- `ResponseService`: quarantine with duration, reason and evidence;
  extend-on-repeat; release; expiry sweep; startup reconciliation;
  protected-host, outside-lab and concurrency-cap refusals (audited and
  emitted); automatic quarantine at CRITICAL, ALERT at HIGH.
- Persistent per-quarantine recovery jobs, a 60 s sweep, and a 15 min periodic
  risk re-score.
- Hash-chained, append-only audit log with `GET /api/audit/verify`.
- Signed MQTT commands to the ESP32 status node (HMAC-SHA256, id/ts/ttl) and
  ack auditing. paho-mqtt v2 client with TLS and reconnect backoff.
- API: `/api/quarantines` (GET/POST), `/api/quarantines/{id}/release`,
  `/api/devices/{id}/approve`, `/api/audit`, `/api/audit/verify`. Mutations need
  `DSN_ADMIN_TOKEN`.
- CLI: `quarantine`, `release`, `audit`, `demo-phase4`. Tasks:
  `docker-test-nft`, `demo-phase4`.
- `infra/docker-compose.gateway.yml` + `infra/gateway.Dockerfile` for real
  enforcement (host network, NET_ADMIN/NET_RAW only, file capabilities on nft/nmap).
- CI job `enforcement`: driver tests against real nftables in a NET_ADMIN container.

### Fixed / found during this phase
- CLI quarantine/release now reconcile first. On a fresh gateway,
  `nft add element` would fail because the table didn't exist yet.

### Known limitations
- IP-based quarantine at the gateway: same-segment traffic that bypasses the
  gateway isn't blocked. The admin token is a single shared secret until
  Phase 6. The audit chain detects tampering but doesn't prevent it.

## [0.4.0] Phase 3: Explainable risk engine, 2026-10-07

### Added
- **Linear risk scorer** (`config/risk.yaml`): five factors in [0, 1], weights
  validated to sum to 1, thresholds LOW/MEDIUM/HIGH/CRITICAL, actions per
  level. Contributions sum exactly to the score.
- **Risk engine:** factors with typed evidence (detections, CVE/KEV matches,
  IOC contacts, actor links), human-readable explanation, recommended action
  (protected hosts never `quarantine`), graph evidence paths, persisted
  `risk_decisions`, `RISK_UPDATED` / `THREAT_CORRELATED` events, event-driven
  reassessment.
- **XGBoost + SHAP** comparison model (TreeExplainer, local + global), stored as
  signed JSON, attached to each decision for the most anomalous lookback window.
- **Ablation** notebook (executed) with CSVs and ROC/SHAP plots in `docs/evaluation/`.
- Graph: `related_from_node`, `indicators_for`, `node_by_name` (both stores).
- API `/api/risk*`; CLI `risk`, `demo-phase3`; `make ablation`.
- Hypothesis properties: score in [0, 100], monotonic per factor, contributions
  sum to the score.

### Fixed / found during this phase
- Events now carry domain time (observation / window end), so risk lookbacks
  work in replays. Detections are published only after commit.
- The risk engine checks IOC contacts and runs the ML explanation over the whole
  lookback, not just the latest window (a C2 contact before a quiet window was
  being missed).
- Isolation Forest scoring is batched per window-close step (it was about 60 ms
  per call), and the forest uses 100 trees (same accuracy over 20 seeds).
- The ablation showed the IF could not see connect/auth features that are
  constant in training. The simulator now includes benign MQTT reconnects with
  occasional auth failures (more realistic, and IF AUC 0.85 → 0.89).

### Verification
- Detection over 20 seeds: 140/140 attack windows, 0 FP / 3,453 normal windows (z + IF).
- Ablation (held-out seeds 1-10, 4,760 windows): pipeline precision 1.000,
  recall 0.969, FPR 0. Table in docs/architecture.md.

### Known limitations
- Simulated traffic only. Expert-set weights. CPE guesses can be wrong
  (discounted by confidence). Quiet devices aren't re-scored until Phase 4's
  periodic job.

## [0.3.0] Phase 2: Device detection & behavior, 2026-10-07

### Added
- **Device registry:** HMAC identities with stable `dev-…` node IDs;
  provisional IP identities upgraded in place; DHCP reassignment handling; OUI
  vendor lookup (IEEE MA-L/M/S, 58k prefixes, longest match, randomized-MAC
  detection); service fingerprint → CPE 2.3 guesses with confidence; trust
  states with an allowlist (by MAC or HMAC) and approval.
- **Discovery:** nmap (lab CIDR only, fixed profiles, DRY_RUN prints the plan,
  defusedxml parsing); passive ARP/DHCP/mDNS (scapy, listen-only); BLE
  advertisements (bleak, passive); Wi-Fi deauth/disassoc rate per BSSID. Each
  has a flag and a capability check (`/api/discovery/capabilities`).
- **Behavior:** 12 per-window features; Welford baselines (log scale,
  Chan merge) with a cold-start fleet fallback; HMAC-signed Isolation Forest;
  combined score with top-feature explanations; learning from clean windows only.
- **Rules:** YAML DSL (typed, never `eval`'d) with 7 rules mapped to ATT&CK,
  each justified; linked into the graph after every ATT&CK import.
- pcap → TrafficEvent converter (TCP SYN, plaintext MQTT, refused CONNACK,
  DNS); seeded traffic simulator with attack injectors.
- Typed in-process event bus (`DEVICE_CONNECTED`, `DEVICE_PROFILED`,
  `ANOMALY_DETECTED`, …) with a recent-events API.
- Alembic migrations (Phase 1 DBs are stamped and upgraded, history kept).
- API: devices, detections, events, rules, capabilities. CLI: devices, approve,
  discover-xml, scan, replay, train-model, rules, `demo-phase2`.

### Fixed / found during this phase
- `.gitignore`'s bare `data/` hid `app/intel/data/tlds.txt` from git, so CI
  failed on every NLP test (now anchored). CI failures are now annotated per test.
- ATT&CK for ICS revoked T0855; the restricted-publish rule maps to its
  replacement T1692.001.
- False positives: byte variance from 1–2 events was noise, and linear-scale
  z-scores flagged periodic housekeeping. Fixed with log-scale baselines and a
  minimum sample size for variance. Measured over 20 seeds: z + IF 0 FP /
  3,455 normal windows (was 29 FP / 1,724 with z alone on a linear scale).
- Scans no longer count as authentication failures. DNS replies are no longer
  counted as requests. mDNS records chained inside list sections are parsed.

### Verification
- See the docs/architecture.md Phase 2 section for detection measurements
  (simulated traffic).

### Known limitations
- Thresholds and the IF are validated on simulated traffic only. BLE identities
  are weak (rotating addresses). TLS MQTT is opaque in pcaps. Live
  capture/radio paths are tested with crafted packets and fakes, not hardware.

## [0.2.0] Phase 1: Threat-intel layer, 2026-10-06

### Added
- **Feed adapters** behind one `FeedAdapter` interface (`fetch`,
  `normalize_to_stix`): CISA KEV, NVD CVE 2.0 (incremental, paginated,
  optional API key), MITRE ATT&CK enterprise + ICS, abuse.ch URLhaus /
  ThreatFox / Feodo, and a dark-web interface with a generic env-configured
  REST provider. `MockAdapter` replays `/fixtures` through the real parsers.
- **HTTP layer:** token-bucket rate limiter, retry with exponential backoff,
  full jitter and `Retry-After`, ETag/Last-Modified disk cache, streamed
  response size caps, no redirects (auth headers can't leak).
- **STIX 2.1:** deterministic UUIDv5 IDs (KEV and NVD merge into one CVE node),
  escaped and grammar-validated patterns, and every object validated with
  `stix2.parse`. Invalid items are rejected and counted, not fatal.
- **Graph:** `GraphStore` contract with Neo4j and in-memory implementations that
  share the projection and query logic. Constraints and indexes; provenance
  (sources, first/last seen, max confidence); indicator TTL aging (stale, then
  purge); `related_threats`, `cves_for_cpe` (NVD range semantics),
  `techniques_for_behavior` / `link_rule`.
- **NLP:** sanitizer (NFKC, invisible/bidi/ANSI stripping) plus regex extractors
  (CVE, IPv4/6, IANA-validated domains, hashes, defang-aware) and spaCy
  EntityRuler (ATT&CK IDs, malware/actor names seeded from the graph). Each
  entity carries confidence and source span.
- **Scheduling:** persistent APScheduler jobs per feed plus hourly aging;
  `feed_runs` history; `GET /api/feeds/status`.
- Read-only intel API (`/api/intel/*`), CLI (`python -m app.cli`),
  `make demo-phase1`, `make docker-test`, `make docker-demo-phase1`.
- Fixtures built from real public data by `scripts/build_fixtures.py`, plus
  synthetic URLhaus/ThreatFox/dark-web samples (reserved IPs and domains only).
- `lab` optional-dependency extra. The hosted (Vercel) app imports none of it,
  which a CI test enforces.

### Fixed / hardened (found during this phase)
- spaCy's tokenizer is roughly quadratic on long whitespace-free runs (20k `:`
  took 49 s). Long runs are now masked before tokenization, and an adversarial
  test guards it.
- Sanitizer turned `\r\n` into `" \n"`; CRLF is now normalized first.
- `related_threats` returned duplicates across indicators and same-name nodes,
  and gave far paths the same score as direct ones. Results are now one per
  threat, and confidence decays ×0.85 per extra hop.
- CLI logs go to stderr so JSON on stdout stays parseable.

### Verification
- 236 tests on Linux (Docker, spaCy, Neo4j 5.26) at 97% coverage. Locally on
  Windows, spaCy- and Neo4j-dependent tests skip (Smart App Control blocks
  spaCy's DLLs).
- Live formats verified 2026-10-02/06: KEV, NVD (record shape and
  `lastMod*` date format), ATT&CK bundles, Feodo. URLhaus and ThreatFox return
  401 without `Auth-Key`, so their response shapes are **unverified**.

### Known limitations
- Same-name entities from different sources stay separate nodes; queries
  deduplicate by name. NVD AND-configurations are flattened. Version comparison
  is heuristic. The in-memory graph is per process. No migrations yet
  (`create_all`). APScheduler's job store pickles jobs, so the DB must be
  app-trusted (threat model F8). Details in `docs/architecture.md`.

## [Unreleased: Vercel]

### Added
- Vercel deployment: `vercel.json` (static frontend, FastAPI function at
  `/api/*`, security headers, SPA fallback), `api/index.py`, `.vercelignore`,
  and a root `requirements.txt` exported from `uv.lock` with a CI drift check.
- `DSN_DEPLOYMENT` (`lab` | `hosted`). Hosted is forced by the Vercel
  entrypoint, and settings validation rejects it with `DRY_RUN=false`.
  `/api/health` now reports `deployment`.

### Fixed
- CI: pin `astral-sh/setup-uv@v10.2.0`. That action publishes no floating major tag.

### Known limitations
- The Vercel deployment was not run end to end (no Vercel account linked in
  this environment). The entrypoint is covered by tests with Vercel-like env vars.

## [0.1.0] Phase 0: Scaffold, 2026-10-02

### Added
- Repo layout for backend, frontend, firmware, infra, fixtures and docs.
- Typed settings (`DSN_*`, pydantic-settings) with fail-fast validation: HMAC
  key at least 32 bytes, explicit CORS origins (https in production), private
  `lab_cidr`, paired credentials. `DRY_RUN` and `OFFLINE_MODE` default to on.
- Structured JSON logging with secret redaction (keys and values) and
  log-injection hardening.
- `DeviceIdHasher`: HMAC-SHA256 device IDs from normalized MACs.
- `/api/health` (liveness) and `/api/health/ready` (pluggable checks, 503 on error).
- Security headers, validated `X-Request-ID`, CORS allowlist, OpenAPI off in production.
- docker-compose: Mosquitto (closed by default), Neo4j, backend (non-root,
  read-only, no caps) and frontend (nginx, non-root, CSP). Ports bound to localhost.
- Minimal React + TS status page (health, readiness, DRY-RUN badge).
- CI: ruff, mypy `--strict` (Python 3.11 and 3.13), pytest with an 80% coverage
  gate, frontend build, compose validation, Phase 0 demo.
- Cross-platform task runner (`scripts/tasks.py`) with a `Makefile` wrapper.
- `docs/architecture.md`, `docs/threat-model.md`.

### Known limitations
- No API authentication yet. Acceptable only because Phase 0 exposes read-only
  health data on localhost. It is tracked in the threat model (O1).
- Mosquitto accepts no clients until Phase 5 adds credentials, TLS and ACLs.
- Readiness checks for database, Neo4j and MQTT are placeholders
  (`not_configured`) until those subsystems land.
- The Docker images were not built locally (Docker daemon unavailable). The
  compose file was validated with `docker compose config`, and image tags were
  verified to exist on the registries.
- mypy uses `native_parser = false` because Windows Application Control blocks
  mypy 2.x's native parser DLL on the development machine.
