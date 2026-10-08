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
│  feeds/ ✅P1 ──► intel/ (NLP) ✅P1 ──► graph/ (STIX 2.1 → Neo4j) ✅P1                  │
│                                              ▲                                         │
│  detect/ ✅P2 ──► behavior/ ✅P2 ──► risk/ ✅P3 ──► response/ ✅P4 ──► nftables/DRY-RUN  │
│     ▲   (nmap, ARP/DHCP/mDNS, BLE)     │ explanations                 │                 │
│     │                                  ▼                              ▼                 │
│  mqtt/ ✅P4-5 ◄──── telemetry ──── api/ + Socket.IO ⏳P6       audit log (DB)           │
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
│ virtual lab  │  IoT devices + status node (NORMAL/ALERT/QUARANTINED) ✅P5
│ (containers) │
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

## Phase 1: threat-intel layer

### Pipeline

```
FeedScheduler (APScheduler, SQL job store; one interval job per feed + hourly aging)
   │  run_feed_job(name)
   ▼
FeedRunner.run(name)
   ├─ build_adapter()  live adapter, or MockAdapter(real adapter, /fixtures/...) when offline
   ├─ adapter.fetch()                HttpFetcher: token bucket → retry (exp. backoff, full
   │                                 jitter, Retry-After) → ETag/TTL disk cache → size cap
   ├─ adapter.normalize_to_stix()    stix2 objects, each round-tripped through stix2.parse;
   │                                 invalid items are rejected and counted, not fatal
   ├─ project()                      STIX dicts → graph records (labels/rel types whitelisted)
   ├─ GraphStore.upsert()            provenance merge: sources ∪, first_seen, last_seen, max(conf)
   └─ feed_runs table                status, counts, redacted error  →  GET /api/feeds/status
```

| Feed | Adapter | Live endpoint | Output | Format verified |
|---|---|---|---|---|
| CISA KEV | `kev.py` | cisa.gov KEV JSON | Vulnerability + `x_dsn_kev` | ✅ live, 2026-10-02 |
| NVD CVE 2.0 | `nvd.py` | `lastMod*` window, paginated, optional `apiKey` header | Vulnerability + CVSS + CPE match rules | ✅ live (record shape and date-param format) |
| MITRE ATT&CK | `attack.py` | attack-stix-data enterprise + ICS bundles | pass-through SDOs/SROs (revoked/deprecated dropped) | ✅ live |
| Feodo Tracker | `abusech.py` | `ipblocklist.json` | `ip:port` Indicator → indicates → Malware | ✅ live |
| URLhaus | `abusech.py` | `/v1/urls/recent/` + `Auth-Key` | URL + host Indicators | ⚠️ 401 without key; shape from docs, unverified |
| ThreatFox | `abusech.py` | `POST /api/v1/ get_iocs` + `Auth-Key` | Indicators (+port) → Malware | ⚠️ 401 without key; shape from docs, unverified |
| Dark web | `darkweb.py` | generic licensed REST provider (env-mapped fields) | Indicators, Vulnerability stubs, Report | ⚠️ no provider; mock-tested only |

**Deterministic IDs.** Every SDO DSN creates gets `uuid5(namespace, natural key)`,
so KEV and NVD records for one CVE, or one IP reported by two feeds, converge on
a single node. ATT&CK objects keep MITRE's IDs.

**STIX patterns from untrusted values.** Values are escaped (`\` then `'`)
before interpolation, and `stix2` validates every pattern's grammar. A feed
value cannot break out of the literal.

### Graph model (Neo4j and in-memory store share it)

```
(:StixObject:<AttackPattern|Malware|Tool|IntrusionSet|Campaign|Vulnerability|Indicator|Report|Identity|CourseOfAction>
   {id, name, name_key, alias_keys, sources[], first_seen, last_seen, confidence, stale, ttl_days, stix_json, ...})
(a)-[:USES|INDICATES|MITIGATES|ATTRIBUTED_TO|SUBTECHNIQUE_OF|... {id, sources, confidence}]->(b)   STIX SROs
(:Report)-[:REFERS_TO]->(x)              object_refs
(:Report)-[:MENTIONS]->(AttackPattern | named threat)   NLP technique IDs / names linked to existing nodes
(:Indicator)-[:OBSERVES]->(:Observable {key: "ipv4-addr:1.2.3.4"})
(:Vulnerability)-[:AFFECTS {version_* range}]->(:CPE {criteria, part, vendor, product, version})
(:DetectionRule {rule_id, rationale})-[:DETECTS]->(:AttackPattern)
```

Constraints: unique `StixObject.id`, `Observable.key`, `CPE.criteria`,
`DetectionRule.rule_id`. Indexes: `AttackPattern.external_id`,
`CPE(vendor, product)`, `Indicator.last_seen`, `StixObject.name_key`.

**Aging.** Only Indicators age. Past `ttl_days` (per feed) without being re-seen,
an indicator is marked `stale`; past `2 × ttl_days` it is deleted, along with
orphaned Observables. Re-ingestion clears `stale`. Vulnerabilities and ATT&CK
never age.

### Queries

| Function | Semantics |
|---|---|
| `related_threats(ioc, max_hops=3)` | IOC (defanged OK) → Observable → Indicators → paths of 1..3 hops over STIX relationships. **AttackPattern / Vulnerability / CourseOfAction are terminal:** paths may end there but not pass through, because a shared technique is not attribution. Identity is never traversed. One result per (type, name), best path wins (fewest hops, then confidence). Path confidence = weakest node × 0.85 for each hop beyond the first. Each result carries its full evidence path. |
| `cves_for_cpe(cpe)` | Candidate CPE rules by vendor+product, then NVD range semantics (`versionStart/End Including/Excluding`) in Python. Match kinds: `exact`, `range`, `unversioned`, `any-version` (input without version). Sorted KEV first, then CVSS. |
| `techniques_for_behavior(rule_id)` | Techniques linked by `link_rule()`. Phase 2's YAML rules call `link_rule` with the justification as `rationale`. |

### NLP (`app/intel/nlp.py`)

Input is sanitized first (`sanitize.py`): NFKC normalization (folds fullwidth
digits), zero-width/bidi characters removed, ANSI and control characters
neutralized, length capped at 100k. Spans index the sanitized text, which is
returned with the entities.

| Entity | Method | Confidence |
|---|---|---|
| CVE | regex (accepts Unicode dashes) | 0.97; 0.4 if the year is implausible |
| IPv4 | regex + `ipaddress`, defang-aware | 0.85 plain / 0.95 defanged; 0.25 after "version"/"v"; ≤0.5 if not globally routable |
| IPv6 | regex + `ipaddress` | 0.85; 0.5 if not global |
| Domain | regex + IANA TLD list (bundled), defang-aware | 0.7 plain / 0.9 defanged; 0.3 if the TLD is also a file extension (`.md`, `.zip`, `.sh`) |
| MD5/SHA1/SHA256 | regex, strict boundaries | 0.9; 0.3 for low-entropy strings |
| ATT&CK technique | spaCy EntityRuler token regex | 0.95 if in the local ATT&CK graph, else 0.6 |
| Malware / actor / tool / campaign | spaCy EntityRuler, case-insensitive, gazetteer seeded from the graph | 0.85 canonical name / 0.75 alias; ambiguous and stopword aliases dropped |

**DoS hardening.** All regexes are linear-time; tests run 80k-character
adversarial inputs against them. spaCy's tokenizer is roughly quadratic on long
whitespace-free runs (measured: 20k `:` took 49 s), so runs longer than 64
characters are blanked out to equal-length padding before spaCy sees the text.
Offsets are preserved.

**Dark-web mentions** become Indicators and Vulnerability stubs for entities with
confidence ≥ 0.5, plus one Report that references them and records technique IDs
and threat names. The Report is linked to existing ATT&CK nodes via `MENTIONS`.
Feed confidence is 40, multiplied by entity confidence. No `indicates` or
`attributed-to` relationships are invented from co-occurrence.

### Lab vs hosted footprint

The `lab` extra (spaCy, neo4j, stix2, APScheduler, SQLAlchemy, httpx2) is
imported only via `app.runtime`, which `app.main` loads lazily when
`deployment == "lab"`. `tests/test_hosted_footprint.py` blocks those packages and
runs the Vercel entrypoint, so a leaked import fails CI.

### Known limitations (Phase 1)

- **Same-name entities from different sources stay separate nodes.** For
  example, Feodo's "Emotet" (DSN ID) and ATT&CK's Emotet (MITRE ID) are not merged.
  Queries deduplicate by name, and NLP Reports link to the ATT&CK node by
  alias. A deliberate `SAME_AS` merge is a Phase 3 candidate.
- **NVD AND-configurations are flattened.** For example, "firmware X on hardware
  Y" becomes "firmware X". This over-reports rather than under-reports.
- **Version comparison is heuristic.** Numeric and alphabetic runs are compared
  in order; vendor pre-release semantics are not modelled.
- **CPE lookups need NVD data.** KEV alone carries vendor/product names, not CPEs.
- **The in-memory graph is per process.** CLI query commands only see data in
  the same process unless Neo4j is configured.
- **Schema creation uses `create_all`**, with no migrations yet. Alembic is planned
  when the device schema lands (Phase 2).

## Phase 2: device detection & behavior

```
nmap (lab CIDR only, DRY_RUN → plan) ┐
passive ARP / DHCP / mDNS (scapy)    ├─► Observation ─► DeviceRegistry ─► devices table
BLE advertisements (bleak, passive)  │   (sanitized)    HMAC identity, OUI vendor,       │
traffic sources (pcap / sim / MQTT)  ┘                  services → CPE guesses, trust    ▼
                                                                          DEVICE_CONNECTED / PROFILED
TrafficEvent ─► BehaviorPipeline: 60 s tumbling windows (event time)
   features ─► baseline view (device | fleet | none) ─► AnomalyScorer (z + Isolation Forest)
            └► RuleEngine (YAML DSL → ATT&CK)       ─► detections table + ANOMALY_DETECTED
   learn ONLY from clean windows ─► device_baselines table
Wi-Fi deauth monitor ───────────────────────────────► detection (wifi_deauth_flood)
```

**Identity.** `node_id = "dev-" + HMAC(key, MAC)[:16]`, stable and safe to show.
IP-only sightings attach to the device holding that IP, or become a
provisional `ip` identity that is upgraded in place (same node_id) once a MAC
is seen. DHCP reassignment moves the IP to the new holder. BLE devices on
macOS (UUIDs, not MACs) use a namespaced `alt_id`. Randomized (locally
administered) MACs are flagged and get no vendor.

**Trust.** `approved` (allowlist in `config/devices.yaml`, by MAC or HMAC, or
`cli approve`) > `known` (present ≥ 24 h) > `unknown`. Trust is input to the
Phase 3 "unknown device" factor. It is *not* the protected-host allowlist that
guards enforcement (Phase 4).

**CPE guesses.** nmap's own CPEs (service and OS; 2.2 URIs converted to 2.3 with
correct escaping, e.g. `%2f` → `\/`) beat a small product table. One guess per
product, each carrying confidence and basis. Phase 3 feeds them to
`cves_for_cpe`.

**Features** (per device per window, rates per minute): request_rate,
unique_destinations, unique_dst_ports, failed_attempts (authentication
failures only; a refused SYN is not a failed login), proto_entropy,
bytes_mean, bytes_var, dns_rate, mqtt_connect_rate, mqtt_wildcard_subs,
mqtt_restricted_publishes, new_protocols.

**Baselines.** Welford (n, mean, M2) per feature, merged with Chan's formula,
kept on **log1p(x)** so z-scores measure ratio changes. Rates and byte sizes
are heavy-tailed and periodic; on a linear scale a device's normal 5-minute
housekeeping call looked like a 4σ outlier. `bytes_var` is ignored below 5
events per window (a variance from 1–2 samples is noise). Std is floored:
`max(std, 0.1·|mean|, 0.5)`. Cold start: under 30 clean windows a device is
scored against the fleet baseline (flagged `cold`); without a mature fleet
baseline, only the Isolation Forest and the rules apply. Anomalous or
rule-hit windows are never learned (anti-poisoning), and learning stops at
`max_windows`.

**Isolation Forest.** Trained on seeded simulated normal traffic (log1p
features), calibrated with the training-score p50/p99. The joblib file is a
pickle, so it is **HMAC-signed with the platform key and verified before
deserialization**. A tampered model is rejected and retrained.

**Combined score** = weighted mean of `min(1, max|z|/6)` and the calibrated IF
component (weights 0.5/0.5, renormalized when one is missing). Threshold
0.6. Results carry the top-3 z-score features for explanation.

**Measured (simulator, 20 seeds, 3,455 normal / 140 attack windows):**
z + IF detected 140/140 attack windows with 0 false positives. z-scores alone
detected 140/140 with 10 false positives (0.29%). This is synthetic traffic
only; Phase 7 evaluates on labelled datasets.

**Rules** (`config/rules.yaml`, typed DSL, never `eval`'d; every mapping
justified in comments and a `rationale` stored on the graph's DetectionRule):

| Rule | Techniques |
|---|---|
| mqtt_connect_flood | T1498, T1499 |
| mqtt_wildcard_subscription | T1040 |
| mqtt_restricted_publish | T1692.001 (ICS Command Message; replaces revoked T0855) |
| credential_brute_force | T1110, T1110.001 |
| network_scan | T1046 |
| protocol_drift | T1071 |
| wifi_deauth_flood | T1498, T0814 |

Rules are linked into the graph at startup and again after every ATT&CK
import, so `techniques_for_behavior(rule_id)` works.

**pcap → events.** One event per *request*: TCP SYNs (port → protocol),
plaintext MQTT control packets (topics parsed, bounds-checked), refused
CONNACKs as failed CONNECTs for the client, and DNS queries. Service replies
are skipped. TLS MQTT (8883) payloads are opaque.

**Schema.** Alembic migrations (`backend/migrations`): 0001 is the Phase 1
`feed_runs`, 0002 adds devices, detections and device_baselines. Phase 1
databases (created with `create_all`) are stamped at 0001 and upgraded,
keeping run history.

### Known limitations (Phase 2)

- Behavior thresholds and the IF were tuned and validated on **simulated**
  traffic. Real lab traffic needs a calibration period (Phase 7).
- BLE identities are weak: most devices rotate random addresses.
- MQTT over TLS cannot be parsed from pcaps. MQTT-specific features need the
  broker-side telemetry consumer (Phase 5) or plaintext 1883 in the lab.
- Passive capture, BLE and Wi-Fi monitoring were tested with crafted packets
  and fakes, not live radios or interfaces in CI.
- nmap OS CPEs in the fixture are synthetic. Real nmap OS CPEs are often
  coarser (vendor/product without firmware version).

## Phase 3: explainable risk engine

```
bus events (DEVICE_CONNECTED / DEVICE_PROFILED / ANOMALY_DETECTED, domain-timestamped)
   └─► RiskEngine.assess(node)
         factors (each value in [0,1], each with typed evidence)
           unknown_device      trust: unknown 1.0 · known 0.25 · approved 0
           rate_anomaly        max(anomaly score, severity of flood/scan/brute/deauth rules), 15-min lookback
           protocol_anomaly    max(severity of drift/wildcard/restricted rules, 0.3 if new protocol now)
           threat_intel        max(KEV CVE on device, IOC contact in lookback, actor/campaign link)
                               (single low-confidence source capped at 0.5: threat model F1)
           vulnerable_service  max(CVSS/10 x CPE-guess confidence x match quality)
         linear score = sum(w_f * v_f * 100)   (config/risk.yaml, weights sum to 1)
         level by thresholds -> action (protected hosts never "quarantine")
         explanation text + evidence paths (Device->CPE->CVE, Indicator->...->Malware/Actor)
         + XGBoost probability & SHAP (comparison only)
   └─► risk_decisions table · RISK_UPDATED (on change) · THREAT_CORRELATED (first intel hit)
```

**Machine-readable decisions.** Each decision stores, per factor, (value,
weight, contribution) with contribution = round(weight × value × 100, 2), and
the score is the exact sum. Property tests (Hypothesis, random valid configs)
check that the score stays in [0, 100], the contributions sum to the score,
and the score is monotonic in every factor.

**Evidence paths.** CVE evidence is `Device → RUNS → CPE → AFFECTED_BY →
Vulnerability`. IOC and actor evidence reuse the Phase 1 graph paths (e.g.
`Indicator → INDICATES → Malware`). `related_from_node` also finds actors that
reach a KEV CVE through dark-web Reports. Lab-internal destinations are never
treated as IOCs.

**Domain time.** Bus events carry observation or window time, not publish
time, so lookbacks behave the same in replays and live operation.

**XGBoost + SHAP (comparison only).** Supervised on simulated labelled windows
(seeds 100–109; evaluation seeds 1–20 are disjoint), using the log1p behavior
features. `shap.TreeExplainer` gives exact local attributions in log-odds:
base + Σ SHAP = logit(p), which is tested. Global importance is mean |SHAP|. The
model is stored as XGBoost JSON (not a pickle) and HMAC-signed. Each decision
explains the device's *most anomalous* window in the lookback.

### Ablation (docs/evaluation/ablation.ipynb, executed)

Held-out seeds 1–10: 4,760 windows, 160 attack windows. Measured:

| method | ROC-AUC | precision | recall | FPR |
|---|---|---|---|---|
| rules | 0.969 | 1.000 | 0.938 | 0 |
| z-score | 0.950 | 0.837 | 0.675 | 0.0046 |
| Isolation Forest | 0.894 | 0.864 | 0.119 | 0.0007 |
| z + IF (combined) | 0.936 | 1.000 | 0.669 | 0 |
| **pipeline (rules OR combined)** | 0.984 | **1.000** | **0.969** | **0** |
| linear risk (window part) | 0.997 | 0.802 | 0.888 | 0.0076 |
| XGBoost (in-distribution upper bound) | 1.000 | 0.994 | 1.000 | 0.0002 |

Takeaways:
- The rules carry most of the detection.
- The Isolation Forest is weak alone: it can't split on features that are
  constant in normal training data (wildcard and restricted publishes). Its
  value is suppressing z-score false positives (z alone: 21 FP → z + IF: 0).
- The transparent linear scorer ranks almost as well as XGBoost (AUC 0.997 vs
  1.000) while staying fully explainable.
- XGBoost's perfect score is an artifact of training and testing on the same
  generator.

All of this is **simulated** traffic. Phase 7 re-measures on labelled data.

### Known limitations (Phase 3)

- Weights and thresholds are expert-set, not learned. The ablation shows the
  ranking is good but the operating point is a policy choice.
- A device's CPE guesses are inferred; wrong guesses produce wrong CVE
  evidence, discounted by guess confidence and match quality.
- Risk is reassessed on events. A device that goes quiet keeps its last score
  until the next event (periodic re-scoring is a Phase 4 scheduler job).
- XGBoost is only as good as its labels: simulated attacks here.

## Phase 4: response (quarantine & recovery)

```
RISK_UPDATED{action=quarantine} ─┐            ┌── manual: POST /api/quarantines (Bearer DSN_ADMIN_TOKEN), CLI
                                  ▼            ▼
                    ResponseService.quarantine(node, reason, minutes, evidence)
                      refuse (audited + emitted): protected host · outside lab_cidr ·
                                                  > max_active_quarantines · no IP
                      QUARANTINE_STARTED → quarantines row (desired state) → driver.quarantine(ip)
                      → audit (hash chain) → persistent recovery job → MQTT QUARANTINE (signed)
                      → QUARANTINE_COMPLETED{ok}
   recovery job / 60 s sweep / manual release:
                      RECOVERY_STARTED → driver.release(ip) → row released → audit → MQTT RECOVER
                      → DEVICE_RESTORED
   startup: reconcile() = release expired + atomic table replace seeded with desired IPs
```

**Drivers.** `NftablesDriver` (preferred) owns `table inet dsn` with sets
`quarantine_v4`/`quarantine_v6`, plus forward and input chains that drop in
both directions. Element add/delete are single atomic commands. `ensure_ready`
replaces the whole table atomically (add, delete, then define, in one `nft -f`
transaction), seeded with the desired state, so reconciliation never opens a
gap. `IptablesDriver` uses a dedicated `DSN-QUARANTINE` chain with
check-before-add idempotency (two rules per IP, so not atomic). `DryRunDriver`
records the exact commands it would run. **`DRY_RUN=true` always selects
dry-run.** A configured driver that is unavailable falls back to dry-run and
readiness reports `response: error`, failing safe and loudly. All IPs are parsed
with `ipaddress` before any command is built, and commands are argv lists with
no shell. Verified against real nftables in a `NET_ADMIN` container (CI job
`enforcement`).

**State & reconciliation.** The `quarantines` table is the source of truth
(active / released / failed, expiry, actor, evidence, driver, dry_run). At
startup and from `reconcile`, expired rows are released first, then the
firewall is replaced to match the DB. Stray elements (added by hand) are
removed and missing ones restored. The diff is audited.

**Recovery.** There is a persistent APScheduler date job per quarantine
(`recover:<id>`), cancelled on manual release. A 60 s sweep (`expire_due`) is
the safety net if a job is ever lost. Re-quarantining an active device extends
its expiry instead of duplicating it.

**Policy.** Automatic quarantine happens only when the risk engine's action is
`quarantine` (CRITICAL) and `DSN_AUTO_QUARANTINE=true`. HIGH sends an ALERT to
the status node without enforcement. Protected hosts (`DSN_PROTECTED_HOSTS`,
plus the MQTT broker IP) and IPs outside `lab_cidr` are refused. At most
`DSN_MAX_ACTIVE_QUARANTINES` (10) are active at once, which guards against mass
quarantine from poisoned intel (threat model E1). A periodic `risk_rescore` job
(15 min) re-assesses quiet devices.

**Audit log.** Append-only `audit_log`, where `hash = SHA-256(prev_hash ‖
canonical JSON(ts, actor, action, node_id, outcome, details))`. Edits,
deletions and reordering break the chain; `GET /api/audit/verify` reports the
first bad id. Actors include `system:risk-engine`, `system:auto-recovery`,
`system:reconcile`, `api:admin`, `cli` and `status-node`.

**MQTT status node.** Commands go to `dsn/cmd/status-node`:
`{id, ts, cmd, node_id, level, ttl, sig}` with `sig = HMAC-SHA256(DSN_MQTT_COMMAND_KEY,
"id|ts|cmd|node_id|level|ttl")`. The status node (Phase 5, `app.lab.status_node`) checks signature, TTL and replay. Acks
on `dsn/ack/status-node` are audited and never gate enforcement. A broker
outage never blocks a quarantine. The client is paho-mqtt v2 with TLS
(certificate and hostname verified), credentials, and reconnect backoff up to
60 s.

**Deployment.** The base compose backend runs unprivileged on a bridge
network, so it can only dry-run. Real enforcement uses
`infra/docker-compose.gateway.yml`: `network_mode: host` so rules land in the
gateway's namespace, only `NET_ADMIN` + `NET_RAW`, and an image with `nft` and
`nmap`. Those file capabilities are granted to the binaries; the Python process
runs as an unprivileged user.

### Known limitations (Phase 4)

- Quarantine is IP-based at the gateway. Traffic between two devices on the
  same L2 segment that never crosses the gateway isn't blocked; that needs
  switch ACLs or 802.1X (out of scope). A device that changes IP escapes until
  rediscovered; the registry follows DHCP changes, and re-quarantine applies to
  the new IP only on the next assessment.
- The admin token is a single shared secret. Phase 6 replaces it with per-user
  auth (JWT/OIDC) and adds rate limits.
- The hash chain makes tampering detectable, not impossible: someone with full
  DB write access can rewrite the chain. Export the head hash elsewhere to
  anchor it.
- The gateway deployment (host network + capabilities) was validated as
  configuration and the driver against real nftables, not on a physical
  gateway in this environment.

## Phase 5: IoT layer (broker + virtual lab)

The project runs entirely in software. Physical devices are replaced by a
**virtual lab**: IoT devices, a status node and scripted misbehavior, each in its
own container, routed through a gateway that captures and really enforces.

```
lab-devices 10.77.1.0/24                                   lab-services 10.77.2.0/24
 cam-front .71   cam-yard .72 (GoAhead 3.6.4)    ┌───────────────────────┐
 thermo-hall .73 plug-lab .74                    │ backend = lab gateway │      mosquitto .10
 sensor-gate .75 status-node .80   ── only ───►  │ .1.2            .2.2  │ ◄──► (TLS 8883)
 rogue-sensor .99 (on demand)      route         │ capture → pipeline    │
                                                 │ nmap 10.77.1.64/26    │
                                                 │ nftables: quarantine  │
                                                 │  + egress lock        │
                                                 └───────────────────────┘
```

**Why route everything through the backend.** Quarantine is IP-based at the
gateway (Phase 4). For it to bite, the device's traffic has to cross the
gateway, so the lab puts devices and broker on different subnets. The backend
container joins both, forwards between them (`net.ipv4.ip_forward=1`), sniffs
the device-facing interface (`DSN_PASSIVE_CAPTURE_TRAFFIC`: every IP packet
becomes a `TrafficEvent`) and runs the nftables driver for real
(`DSN_DRY_RUN=false`). Its rules live in the backend container's own network
namespace, so enforcement is real but confined to the sandbox.

**Isolation.** Docker's `internal` flag can't be used: the host bridge drops
routed packets whose destination is outside the bridge's subnet. Isolation comes
from routing instead:

- `infra/lab/lab-entry.sh` (as root, briefly) removes the on-link subnet route
  and leaves only `gateway/32` + `default via gateway`. Other devices and the
  Docker host bridge (`.1`) are therefore only reachable *through* the gateway.
  It then drops to uid 10001 with an empty capability set (`setpriv`), so the
  client cannot change its routes (verified: `RTNETLINK ... Operation not
  permitted`; `CapEff` = 0).
- `infra/lab/gateway-entry.sh` installs an **egress lock** (`inet dsn_lab`)
  before the app starts and fails closed if it can't: only device ↔ broker
  subnet traffic is forwarded; everything else from the devices (a "C2
  beacon", device-to-device, the host) is captured on ingress and dropped.
- Lab clients get `dns: [127.0.0.1]`, so Docker's embedded DNS can't forward
  outside names for them; the C2 beacon only accepts IP literals.
- The gateway app runs as `dsn` with only `NET_ADMIN` + `NET_RAW` as ambient
  capabilities. `DSN_LAB_CIDR` is `10.77.1.64/26` (lab clients only), so
  scans and quarantines can never target the host bridge or the gateway.

**Lab clients** (`backend/app/lab`, image `infra/lab/client.Dockerfile`, which
contains only `app.lab` and the command contract, no backend settings or secrets):

- `device --profile camera|vulncam|thermostat|plug|sensor`: seeded payloads on
  `home/<user>/…`, telemetry every 10 s, and TCP service banners for nmap.
  `vulncam` answers as `GoAhead-Webs/3.6.4`; nmap reports GoAhead 3.6.4, the
  fingerprint table maps it to `cpe:2.3:a:embedthis:goahead:3.6.4`, and NVD
  marks `< 3.6.5` vulnerable to CVE-2017-17562 (CISA KEV). The fixture records
  for that CVE are the real KEV/NVD entries (merged by `build_fixtures.py`).
- `status-node`: verifies signed commands exactly as `app.mqtt.commands`
  specifies (charset, HMAC in constant time, `|now − ts| ≤ ttl` with ttl ≤ 300 s,
  replay memory of 256 ids, only accepted ids remembered), acks, and publishes
  its state (NORMAL / ALERT / QUARANTINED) in telemetry for the dashboard.
- `attack flood|wildcard|restricted|bad-auth|c2`: signals for the detection
  scenarios. Not exploits: they use the device's own (or a wrong) password
  against the lab broker, or open TCP connections the gateway drops. All refuse
  to run without `DSN_LAB_SANDBOX=1` and a private broker address.

**IOC contact triggers assessment.** Risk was assessed on DEVICE_CONNECTED /
PROFILED / ANOMALY_DETECTED and every 15 min. The lab exposed the gap: a quiet
device beaconing once to a C2 address (no anomaly) waited up to 15 min. The
pipeline now calls window listeners after each batch; the risk engine looks up
destinations it hasn't seen before for that device and re-assesses at once
(`trigger = IOC_CONTACT`) when one is a known indicator.

**Broker.** eclipse-mosquitto 2.0.22, configured as follows:

- **Listener.** A single TLS listener on 8883, using a lab CA with EC P-256 keys. The server certificate's SANs cover the hostnames and IPs passed to `mqtt_provision.py` (the lab adds `10.77.2.10`).
- **Accounts.** `allow_anonymous false`, with `$7$` PBKDF2-SHA512 password hashes. `mqtt_provision.py` writes one credentials file per lab client (`infra/lab/secrets/<user>.json`, gitignored); only the status node's file holds the command key.
- **ACLs.** Deny by default. Patterns bind each device to `dsn/telemetry/%u`, `home/%u/#` and `dsn/config/%u`.
  - `dsn-backend` alone writes `dsn/cmd/#`.
  - `status-node` alone reads its command topic and writes its ack topic.
- **Secret files.** An entrypoint copies the secrets into `/mosquitto/secure` with `mosquitto:0600` ownership, so the broker starts without permission warnings. The log is pre-created `0640 mosquitto:<LOG_READER_GID>` so the non-root backend can tail it. In the lab, `LAB_ROUTE` adds the route to the device subnet via the gateway, so the broker sees real device IPs.
- **Rate limiting.** Mosquitto has no per-client message-rate limit. Instead:
  - Host-level `broker-ratelimit.nft` drops sources that open more than 30 new connections a minute, for 5 minutes.
  - Message floods are a detection case (`mqtt_connect_flood`).

**Broker log as a sensor.** With TLS, packet capture can't see MQTT packets, so the broker log is the only place that sees every CONNECT, authentication failure, SUBSCRIBE and denied PUBLISH:

- `BrokerLogParser` maps client ids to IPs, using the preceding "New connection" line for refused sockets.
- It ignores the configured service clients (`DSN_MQTT_SERVICE_CLIENTS`), so the backend's own `#` subscriptions don't trip rules.
- It emits `TrafficEvent`s carrying `MqttInfo`. These feed the existing features and rules: `mqtt_connect_rate`, `mqtt_wildcard_subs` and `mqtt_restricted_publishes`.
- The tailer follows truncation and rotation.

The formats were captured from a real broker (`fixtures/events/mosquitto.sample.log`).

**Telemetry.** `dsn/telemetry/<user>` carries `{"v":1, mac, ip, fw, uptime_s, rssi, heap, state, seq}`:

- The payload is capped at 2 KiB and validated with pydantic.
- The topic user is trusted because the ACL binds it.
- The MAC is a device-asserted claim.
- When no broker log is configured, telemetry also produces PUBLISH traffic events.

### Known limitations (Phase 5)

- **Simulated devices.** Device behavior is generated, not recorded from real
  products; banners imitate products for fingerprinting and contain no
  vulnerable code. Results measured in the lab say how DSN reacts to these
  signals, not how often real devices emit them.
- **No mutual TLS.** Devices authenticate with passwords; they do not present client certificates.
- **Status-node replay memory is in RAM.** After a restart only the ≤ 300 s staleness window protects.
- **Not internet-isolated by Docker.** The lab networks are ordinary bridges;
  isolation relies on the routing lock, dropped capabilities and the gateway's
  egress lock (all verified), not on Docker's `internal` flag.
- **NAT hides device IPs** outside the lab: if clients reach the broker through NAT (e.g. Docker port publishing), the broker log shows the NAT address. The lab avoids this by routing.
- **No message-rate limit.** There is no per-client message-rate limit at the broker (see above).
- **Indicators added later** for a destination a device already contacted are picked up by the 15-min re-score, not immediately.

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
