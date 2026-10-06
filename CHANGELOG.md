# Changelog

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
