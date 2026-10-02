# Changelog

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
