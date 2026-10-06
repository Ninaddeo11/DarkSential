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
