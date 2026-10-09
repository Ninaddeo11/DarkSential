# Changelog

## [0.12.0] Simulated results for any IP (hosted), 2026-10-09

### Added
- **Any IPv4 address gets a generated scenario on the hosted site** (`frontend/src/sim/generate.ts`).
  - *Trace:* the Network command center shows 3 devices in active communication,
    in 3 countries from a pool of 30, with packet traffic on the map.
  - *Malware:* the intel pages list 3–5 malicious subdomains, each tied to a malware
    family (2–4 of 14 real families, with ATT&CK techniques).
  - *Deterministic:* each scenario is seeded from the address, so the same IP always
    shows the same result.
- **Lab mode is unchanged:** only `138.987.22.22` is simulated, and other lookups
  stay real.

### Notes
- Generated results carry a "Simulated scenario" tag and a one-line footnote, so a
  real address typed at a demo isn't presented as a real accusation.
- Device addresses come from the RFC 5737 documentation ranges, and subdomains are
  random 10–12 character labels.

## [0.11.0] Hosted simulation scenario, 2026-10-09

### Added
- **Simulated investigation for `138.987.22.22`** (`frontend/src/sim/scenario.ts`).
  - *Threat graph:* the indicator links to 4 malware families (Mirai variant, Mozi,
    an XMRig coinminer, RedLine), C2 and hosting infrastructure, an actor, and a
    marketplace listing. A crypto money trail runs through mining payouts, drained
    wallets, a mixer and escrow to a payment for narcotics consignment NX-0427,
    at 18.5204° N, 66.0412° E.
  - *Where it appears:* Threat intel, Actors, Malware and Dark web, with a full
    dossier (`SimInvestigation`).
- **Indicator trace on the Network command center.** Tracing the indicator shows 3
  devices in active communication, Device 1 in Moscow (Russia) and Devices 2 and 3
  in Colombo and Kandy (Sri Lanka).
  - *Map:* a geographic trace (Natural Earth 1:110m via `world-atlas` and `d3-geo`,
    rendered offline) with animated links.
  - *Table:* each device with live packet counters.
  - *Posture:* the panel switches to the traced indicator.

### Changed
- **Hosted (Vercel) mode no longer shows errors or banners.**
  - Reads the deployment can't serve (devices, risk, response, intel) resolve to
    empty data without a request.
  - The top bar shows SIMULATION and the stream status SIMULATED FEED.
  - In the lab, the dry-run / enforcing badge is unchanged.

### Known limitations
- The scenario is fixed data, and only that one indicator is simulated.
- Every identifier is synthetic:
  - `138.987.22.22` is not a valid IPv4 address;
  - device addresses are from the RFC 5737 documentation ranges;
  - wallet strings contain `sim`, which no real Bitcoin address can;
  - domains use `.invalid`.

## [0.10.1] Vercel services, 2026-10-09

### Changed
- **Vercel deploys as two [services](https://vercel.com/docs/services)** in one project:
  - `frontend` (Vite) is public at `/*`, with SPA fallback for paths that have no file extension;
  - `backend` (FastAPI) is public at `/api/*`.
  The backend receives the original path, so its routes are unchanged. Neither service
  calls the other server-side, so there are no bindings.
- The hosted entrypoint moved from `api/index.py` to `backend/vercel_app.py`. It still
  forces hosted, dry-run mode.
- `requirements.txt` moved to `backend/` (core dependencies only), together with CI's
  drift check.
- Security headers are set per service, because `vercel dev` did not apply top-level
  headers in services mode.

### Known limitations
- Tested locally with `vercel dev -L` (CLI 63.1.0), not yet on a real deployment.
  `includeFiles` for `backend/config` inside a service is unverified until then.
- On Windows, `vercel dev` fails if the `uv` path contains a space (CLI quoting bug).

## [0.10.0] Multi-page command center, 2026-10-08

### Added
- **Routed pages** (react-router 8.4.0): Overview, Devices, Device detail, Events,
  Threat intel, Response, Evaluation, and a 404 page. They share one live store and
  one Socket.IO connection (`src/live/LiveContext.tsx`) inside an app shell with a
  sidebar (`src/layout/Shell.tsx`). Its badges count critical and quarantined devices.
- **Device detail page:** the risk-score history plotted against the calibrated
  thresholds (`RiskHistory`), plus detections and recent events.
- **Response page:** quarantine history and the audit log with chain verification.
- **Threat intel page:** IOC and CVE lookups, graph counts, the rules → ATT&CK table.
- **Evaluation page:** `make evaluate` / `regenerate` now copy `summary.json`,
  `lab_runs.csv` and the charts into `frontend/public/evaluation`, and the page
  reads them from there.
- API client: detections, rules, related threats, CVEs, graph counts, risk model,
  audit and audit verification.

### Fixed
- Leaving the Overview threw `removeChild` from the 3D labels. They now render into
  a layer that `Graph3D` owns.
- Component styles (`.input`, `.btn`, ...) moved into `@layer components`, so
  utility classes such as widths override them.

### Known limitations
- The Events page shows only events received since the page was opened, plus the
  replay buffer. There is no server-side event search yet.
- Device pages for devices the browser has not seen yet show "not known (yet)"
  until the snapshot loads.

## [0.9.1] Live-lab evaluation fixes, 2026-10-08

### Fixed (found by `make lab-eval` in the virtual lab)
- **An expired quarantine was never re-applied while the attack continued.**
  - *Cause:* a device that stayed critical at an unchanged score never reached the
    response layer again, because `RISK_UPDATED` was only emitted on score/level
    changes.
  - *Evidence:* the archived run 2 in `docs/evaluation/phase7/lab_runs_pre_fix.csv`
    shows "no automatic quarantine".
  - *Fix:* new evidence (`IOC_CONTACT`, `ANOMALY_DETECTED`) on a quarantine-worthy
    decision is now published even at an unchanged score.
- **Operator decisions win.** Automatic quarantine of a device a human just released
  pauses for `DSN_OPERATOR_RELEASE_GRACE_MINUTES` (default 30), and the skip is
  audited. An automatic expiry does not pause it.
- **A flood from a quarantined lab device no longer hangs.** It used to retry
  1,000 × 3 s timeouts; it now stops after 10 consecutive failed connects.
- **`lab_eval.py` saves results incrementally.** It writes the CSV after every run
  and reports reconnect time in whole seconds, matching the broker log's resolution.

## [0.9.0] Phase 7: simulation and evaluation, 2026-10-08

### Added
- **Seeded evaluation harness** (`app/evaluation`, `make evaluate`). It runs six scenarios through the real runtime:
  - normal fleet;
  - unknown device;
  - MQTT flood at 500/min;
  - KEV device + C2 beacon with decoys;
  - flood + C2 → quarantine → auto-recovery;
  - a vulnerable device that is never attacked.

  Ground truth is tracked per device. Thresholds are calibrated by a fixed rule on seeds 1–10, and every metric is measured on held-out seeds 11–30. CSVs, plots and a generated summary go to `docs/evaluation/phase7`. `make evaluate-report` rebuilds them from the saved data.
- **Live event latency** over a real Socket.IO connection (uvicorn + client, loopback).
- **`make lab-eval`** (`scripts/lab_eval.py`): end-to-end timings in the running virtual lab.

### Changed (driven by the evaluation)
- **Risk thresholds recalibrated** to medium 13.1, high 19.8 and critical 26.4 (previously 25 / 50 / 75). Under the old values no modelled attack could reach critical (the highest reached 48.2), and a flood from an approved device (16.2) didn't alert.
- **Threat intel combines exposure (KEV) and contact (IOC) as independent evidence** (noisy-or across the two channels, max within each). "Vulnerable" and "vulnerable and beaconing to C2" now score 34.8 vs 44–48, instead of 34.8 vs 37.8.
- **Compromise-evidence gate:** the engine recommends automatic quarantine only with observed evidence (a behaviour anomaly or contact with a known indicator). Exposure alone, e.g. KEV firmware scoring 51, goes to `review_quarantine`, and the explanation says why.

### Measured (held-out seeds 11–30, 500 devices)

| metric | before (Phase 3 thresholds) | after |
|---|---|---|
| attacks alerted | 66.7% | 100% |
| benign devices alerted | 0% | 0.25% (1 of 400) |
| corroborated compromises auto-quarantined | 0% | 100% |
| flood-alone, vulnerable-only, unknown or benign auto-quarantined | 0% | 0% |

- C2 correlation: 40/40 contacts correlated, 0/60 decoys.
- Detection after attack start: median 34–38 s (simulated time), max 60 s.
- Risk assessment: 2.3 ms p50.
- Quarantine call: 7.3 ms p50 (dry-run driver).
- Loopback event delivery: 56 ms p50 at a steady rate, 157 ms p50 for a 2,000-event burst.

### Fixed / found during this phase
- Four measurement bugs in the harness were caught before publishing; each would have produced a wrong number:
  - pre-approval scores were counted as scenario data;
  - correlation was read from explanation text;
  - recovery came out at exactly 0 s because the sweep was phase-aligned with expiry;
  - quarantine latency came out negative because of bus delivery order.
- A latent bug in a Hypothesis test strategy could produce a negative weight; it now absorbs float error into the largest weight.
- The Python Socket.IO client presents the server's own origin on direct WebSocket connections, which CORS rejects. Browsers connecting through nginx are unaffected (verified). The live-lab script now connects through nginx.

### Known limitations
- All rates come from simulated traffic and describe responses to the modelled signals.
- The alert threshold (13.1) sits close to normal variation: benign devices reached 12.7 on held-out seeds, and one decoy device reached 17.0 (the false alert).
- Wall-clock timings are from one Windows machine.

## [0.8.0] Phase 6: real-time API and 3D command center, 2026-10-08

### Added
- **Typed event contract** (`app/core/event_schema.py`). There is one payload model per event type, and `EventBus.emit` rejects payloads that don't match. `scripts/gen_event_types.py` generates `frontend/src/generated/events.ts`, and CI fails if that file is stale.
- **Live stream over Socket.IO** (`/api/socket.io`, lab mode):
  - batched (100 ms, up to 1,000 events per message);
  - resumable from `after_seq`, with `resync` when the gap is older than the buffer;
  - authenticated like REST reads.
- **Auth:**
  - `POST /api/auth/login` exchanges `DSN_ADMIN_TOKEN` (operator) or `DSN_VIEWER_TOKEN` (viewer) for an HS256 session JWT;
  - OIDC access tokens are verified against the provider's JWKS (issuer, audience, role claim);
  - `GET /api/auth/me`.

  Mutations need the operator role. Reads need a token in production (`DSN_AUTH_READS`).
- **Rate limits:** per-client token buckets for logins, mutations and reads (`429` + `Retry-After`). Health probes are exempt.
- **3D command center** (React 19, @react-three/fiber, drei, Tailwind 4):
  - a force-directed device graph (risk colours, quarantine pulse, click to inspect);
  - a ranked device list;
  - an inspector with a risk waterfall, SHAP comparison, threat-graph paths and evidence;
  - operator controls (quarantine / release / approve);
  - a virtualized live timeline and feed health.

  Reconnects are handled; renders are coalesced to one per animation frame.
- **Frontend unit tests** (vitest, run in CI), covering the store, layout and waterfall.
- **nginx:** WebSocket proxying for the live stream, and an overwritten `X-Forwarded-For`.
- **`setup`:** fills the missing auth secrets into an existing `.env`.

### Changed
- `DSN_ADMIN_TOKEN` is no longer accepted as a bearer token. Log in to get a session.
- Hosted (Vercel) mode now requires a viewer session for reads, so set `DSN_AUTH_JWT_SECRET` and `DSN_VIEWER_TOKEN` there.
- `cryptography` and `pyjwt` became core dependencies, and `python-socketio` is in the `lab` extra.

### Found while building
- The strict event schema caught two emitters whose payloads didn't match what the dashboard would expect:
  - CPE guesses are objects, not strings;
  - `QUARANTINE_COMPLETED` carries `command_id`.
- The first 3D graph allocated new GPU buffers every frame and broke memoization. It now updates preallocated buffers in place.
- The bounded layout never settled: a node pressed against the radius limit kept its outward velocity. Velocity is now the movement that actually happened after clamping.

### Measured (2026-10-08)
- The live store applied 10,000 events across 200 devices in 5.1 ms (vitest).
- 300 socket messages produced one render frame.
- UI quarantine click to `QUARANTINE_COMPLETED` on screen: 330 ms (headless Edge against the virtual lab, one run).

### Known limitations
- There is no per-session revocation (rotate the JWT secret instead).
- Local login has two shared roles; use OIDC for per-person identity.
- Rate-limit buckets and the event history are per process and in memory.
- The 3D view was not profiled with hundreds of devices.

## [0.7.0] Pure-software lab: virtual IoT devices replace hardware, 2026-10-08

### Changed
- **The ESP32 firmware and all hardware dependencies are removed.** The
  project now runs entirely in software.
- `mqtt_provision.py` writes per-client JSON credential files for the virtual
  lab (`infra/lab/secrets/`) instead of serial provisioning files.
  `--no-firmware` is now `--no-device-files`.

### Added
- **Virtual lab** (`make lab-up`, `infra/docker-compose.lab.yml`). Lab clients are built from `backend/app/lab`:
  - 5 simulated IoT devices (cameras, thermostat, smart plug, air sensor);
  - a virtual status node;
  - an on-demand rogue device.

  The backend container is the lab gateway: it routes, captures, scans and enforces with real nftables, confined to its own network namespace.
- **Isolation by routing.** Each lab client is left with a single route via the gateway, then drops every capability. The gateway's egress lock fails closed and forwards only device ↔ broker traffic. Lab clients cannot resolve outside names.
- **Scenarios** (`lab-attack`): `flood`, `wildcard`, `restricted`, `bad-auth`, `c2` and `rogue`, optionally on a chosen device. All refuse to run outside the sandbox.
- **Live traffic capture** (`DSN_PASSIVE_CAPTURE_TRAFFIC`). The passive sniffer also emits `TrafficEvent`s, batched with a 1 s flush, and ignores the capturing host's own address.
- **`cam-yard` answers as GoAhead 3.6.4.** nmap fingerprints it and it links to CVE-2017-17562 (CISA KEV). The real KEV and NVD records were added to the fixtures.
- **`lab-smoke` and a CI job `lab`:** discovery, the KEV link and the IOC-contact re-score, run end to end. CI also validates the lab and gateway compose files and parses the shell scripts.

### Fixed / found by running the lab
- **Live packet capture never decoded a frame.** The app imported only some scapy modules, so live sockets had no Ethernet binding, and every packet came back raw and was silently dropped. This also affected passive ARP/DHCP/mDNS discovery on real deployments. `start()` now registers the layers, and a regression test runs in a fresh interpreter.
- **A quiet C2 contact waited up to 15 min to be scored.** Risk was assessed only on anomalies and on the periodic re-score. Closed traffic windows now trigger an immediate assessment (`trigger = IOC_CONTACT`) when a device contacts a new known indicator. Measured in the lab: 10 → 42.8 for the smart plug after one beacon.
- **The gateway profiled itself.** Its own nmap probes were captured as "device traffic" and flagged as an anomaly. The capturing host's address is now ignored.

### Measured in the lab (2026-10-08, one run each)
- **Flood scenario:** 1,000 TLS connects in 2 min, measured at 497/min. The `mqtt_connect_flood` rule fired.
- **Flood plus C2 contact:** 42.8 / 100 (medium → alert). With the default thresholds this does **not** auto-quarantine. Automatic quarantine needs *critical*, and the Phase 4 demo lowered its thresholds to show it. Threshold calibration is left to Phase 7, against measured false-positive rates.
- **Operator quarantine of the plug (3 min):**
  - the nft set held 10.77.1.74;
  - the plug ↔ broker connection timed out while other devices were unaffected;
  - the status node showed QUARANTINED;
  - auto-recovery released it 22 s after expiry;
  - the plug reconnected 51 s later.

### Known limitations
- **Device behavior is simulated.** Banners imitate products for fingerprinting only; there is no vulnerable code.
- **Lab isolation depends on routing.** It relies on the routing lock, dropped capabilities and the egress lock, not on Docker's `internal` flag. The `internal` flag drops routed lab traffic on the host bridge.

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
