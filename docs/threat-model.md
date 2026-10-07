# Threat model: the platform itself

Scope: threats **against Darknet Sentinel Nexus**, not the IoT threats it
detects. Method: assets → trust boundaries → STRIDE per boundary → abuse cases
with mitigations. Status: ✅ in place · ⏳ planned (phase).

## 1. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | **Enforcement capability** (firewall rules on the lab gateway) | Misuse can cut off any lab host, including the operator's own. This is the highest-impact asset. |
| A2 | Device registry (HMAC'd MACs, IPs, fingerprints, CPEs) | Inventory of a network and its weak spots. |
| A3 | `DSN_DEVICE_ID_HMAC_KEY` | With it, MACs can be brute-forced back from stored IDs. |
| A4 | Feed / provider API keys (NVD, abuse.ch, dark-web provider) | Licensed, quota-bound, attributable to the operator. |
| A5 | Threat-intel graph (Neo4j) | Poisoning it drives false quarantines or hides real threats. |
| A6 | Risk decisions and audit log | Accountability. Must be tamper-evident and complete. |
| A7 | MQTT broker + ESP32 credentials | Control channel to the physical status node. |
| A8 | Dashboard / API sessions | Operator authority (approve, quarantine, recover). |

## 2. Trust boundaries

```
 [Internet feeds] ──TB1──► [backend] ◄──TB2── [operator browser]
                               │  ▲
                          TB3  │  │ TB4
                               ▼  │
           [Neo4j / DB]     [lab network: IoT devices, broker, ESP32]
                               │
                          TB5  ▼
                      [host firewall (nftables)]
```

- **TB1, internet → backend.** All feed content is untrusted: structured JSON
  *and* free text (dark-web mentions are adversary-authored by definition).
- **TB2, operator → API.** Authenticated humans, but browsers are exposed to CSRF/XSS.
- **TB3, backend ↔ datastores.** Trusted network, but queries are built from
  untrusted strings.
- **TB4, lab devices → backend.** IoT devices are presumed compromisable. Their
  traffic, MQTT telemetry, mDNS names and BLE adverts are attacker-controlled.
- **TB5, backend → firewall.** Privileged. The only path to A1.

## 3. Abuse cases and mitigations

### Feed / intel layer (TB1)

| ID | Abuse case | Mitigations |
|---|---|---|
| F1 | **Intel poisoning:** a feed (or a spoofed dark-web mention) lists the gateway IP or a benign CDN as an IOC so DSN quarantines it. | Protected-host allowlist checked at the response layer, independent of scoring (⏳P4; config ✅). Per-source confidence and provenance (`sources`, `first_seen`, `last_seen`, `confidence`) on every node and edge ✅. Dark-web base confidence 40, multiplied by entity confidence ✅. Co-mentions never become `indicates`/`attributed-to` edges ✅. Path confidence decays per hop ✅. Decisions show their evidence path ✅. Intel backed by a single source below 0.6 confidence is capped at 0.5 (with weight 0.35, at most 17.5 points from intel), so one unverified mention cannot by itself push a device to HIGH ✅ (tested). |
| F2 | **Injection via ingested text:** Cypher, STIX pattern, HTML/JS or log injection through descriptions or forum posts. | Text is never executed ✅. Cypher values are always parameters; labels and rel types are whitelisted by regex ✅ (tested with hostile IOCs). STIX pattern literals are escaped and grammar-validated ✅. Text is NFKC-normalized, invisible/bidi/ANSI characters stripped, length-capped ✅. HTML is stored as inert text; React escapes at display (⏳P6). Control characters are escaped in logs ✅. |
| F3 | **Parser/resource exhaustion:** huge or deeply nested payloads, regex DoS in NLP. | Streamed responses with per-feed byte caps (declared and actual) and timeouts ✅. Linear-time regexes, tested on 80k-character adversarial inputs ✅. spaCy's quadratic tokenizer is guarded by masking long runs ✅ (found by the test suite). `/api/intel/extract` capped at 20k characters ✅. |
| F4 | **Feed MITM / downgrade / redirect.** | HTTPS endpoints with cert verification ✅. Dark-web provider URL must be `https` ✅. Redirects are **not followed**, so `Auth-Key`/`apiKey` headers can't be replayed to another host ✅. |
| F5 | **API key leakage** through logs, errors or repr. | `SecretStr` everywhere ✅. Log redactor masks secret keys and values ✅. Feed run errors are redacted before storage ✅. HTTP errors drop query strings ✅. Health errors expose only the exception type ✅. `.env` git-ignored ✅. |
| F6 | **Rate-limit abuse / ban** from upstream providers. | Per-feed token bucket (NVD: 5/35 s without a key, 45/30 s with one), exponential backoff with full jitter, honors `Retry-After`, ETag/TTL cache ✅. Offline mode by default ✅. |
| F7 | **Malicious fixture/config path** makes the mock adapter read arbitrary files. | Fixture paths must resolve inside `fixtures_dir` ✅ (tested with `../`). ATT&CK domains are allow-listed ✅. |
| F8 | **Schedule tampering** through the persistent job store. | APScheduler 3's SQL job store **pickles** job state, so write access to the DB means code execution in the app. Jobs hold only an importable function reference and a feed name, and are re-synced from `feeds.yaml` at startup ✅. The DB must be treated as app-trusted: it lives in a non-root container volume, and with Postgres (Phase 2) it gets its own credentials. Residual risk, accepted. |

### Lab / device layer (TB4)

| ID | Abuse case | Mitigations |
|---|---|---|
| D1 | **MAC spoofing** to impersonate an approved device or evade quarantine. | MAC is one signal, not identity. DHCP/IP reassignment is tracked ✅. Randomized MACs are flagged ✅. Behavior baselines are per device, so an impostor with different behavior scores anomalous ✅. Fingerprint-conflict risk factor (⏳P3). Residual: a spoofer that mimics behavior is not caught. |
| D2 | **Baseline poisoning:** a device slowly ramps malicious behavior so it becomes "normal". | Windows with an anomaly or rule hit are never learned ✅. Learning stops at `max_windows` ✅. Rules use absolute thresholds that baselines can't shift ✅. The IF trains on curated (simulated) normal data, never on live traffic ✅. Residual: a ramp slower than the z threshold (documented). |
| D3 | **Hostile metadata:** mDNS/DHCP hostnames, BLE names, nmap banners carrying script or ANSI payloads, or XML bombs. | All device strings are sanitized (NFKC, control/bidi/ANSI stripped) and length-capped on `Observation` ✅. Markup characters stripped from hostnames ✅. nmap XML parsed with defusedxml (entity expansion blocked, tested) ✅. MQTT/pcap parsing is bounds-checked and fuzzed ✅. React escapes at display (⏳P6). |
| D4 | **MQTT broker abuse:** floods, wildcard subscriptions, publishing to command topics, credential guessing. | TLS-only listener, no anonymous access, per-client PBKDF2 passwords ✅. Deny-by-default ACLs: devices publish only to `dsn/telemetry/<own user>`, and only the backend may write `dsn/cmd/#` ✅ (tested against a real broker). Broker caps on connections, packet size and queues ✅. Host nft meter limits new connections per source ✅ (validated with real nft). The broker log feeds detection: auth failures, wildcard subscriptions and denied publishes raise `mqtt_*` rules ✅ (tested). Residual: Mosquitto has no per-client message-rate limit, so a message flood from a valid client is detected, not throttled. |
| D5 | **Forged ESP32 acks** to fake that a quarantine LED state was shown. | Per-device credentials, and only `status-node` may write `dsn/ack/status-node` ✅. Acks are matched to pending command ids, audited, and never gate enforcement ✅. |
| D11 | **Hostile telemetry** from a compromised device: oversized payloads, injected markup, spoofed identity. | The topic user is bound by ACL (`dsn/telemetry/%u`). Payloads are capped at 2 KiB, schema-validated with charset-restricted `fw`, and then sanitized like all `Observation` fields ✅ (tested). The MAC in telemetry is device-asserted and treated as a claim (see D1). |
| D12 | **Stolen ESP32** leaks Wi-Fi/MQTT credentials or the command key from flash. | Credentials are entered over serial and kept in NVS, never compiled in ✅. Each device has its own MQTT user, so one can be revoked by re-provisioning ✅. Residual: NVS is not encrypted unless flash/NVS encryption is enabled (not configured). Devices that do not need commands get no command key ✅. |
| D6 | **Scanning outside the lab** through misconfiguration. | `lab_cidr` must be private and non-loopback ✅. Every nmap target is checked with `ipaddress.subnet_of(lab_cidr)` ✅. Scan arguments come only from fixed profiles ✅. Active scans need `DSN_NMAP_ENABLED` **and** DRY_RUN=false; otherwise the plan is printed ✅. Wi-Fi monitoring also requires DRY_RUN=false ✅. |
| D7 | **Malicious ML model file:** a tampered Isolation Forest pickle executes code on load. | The model is HMAC-SHA256 signed with the platform key and verified before unpickling; on mismatch it is rejected and retrained ✅ (tested). The feature-set mismatch check guards against stale models ✅. |
| D8 | **Rule injection:** a rules.yaml edit or a crafted rule executes code. | Rules are a typed declarative tree (all/any/not/compare), interpreted and never `eval`'d. Unknown features, operators, techniques and extra keys are rejected at load ✅ (tested). The file has the same trust level as config. |
| D9 | **Capture privileges abused:** packet capture runs with raw-socket rights. | Passive capture, BLE and Wi-Fi monitoring are off by default and capability-checked ✅. Capture is listen-only (no transmit code paths) ✅. In compose, the API container has no capabilities. Capture should run in a separate container with only `NET_RAW` (⏳P4 alongside the enforcement container). |
| D10 | **Risk manipulation by a device:** a compromised device stays quiet to keep a stale low score, or floods to bury others. | Every risk decision is per device and event-driven. Floods raise only the flooding device's score. Detections and decisions are persisted, so manipulation is visible in history ✅. Periodic re-scoring of quiet devices (⏳P4). |

### Operator / API layer (TB2)

| ID | Abuse case | Mitigations |
|---|---|---|
| O1 | **Unauthenticated control:** anyone on the LAN calls quarantine/recover. | API bound to 127.0.0.1 by default ✅. Published ports bound to localhost ✅. Every mutating endpoint requires a bearer admin token (≥ 32 chars, constant-time compare); without one, mutations are disabled ✅. Never available in hosted mode ✅. Per-user JWT/OIDC + rate limits (⏳P6). |
| O2 | **CSRF / cross-origin abuse** from a malicious site in the operator's browser. | Explicit CORS allowlist, wildcards rejected, https required in production ✅. Bearer tokens rather than cookie sessions (⏳P6). |
| O3 | **Clickjacking / content sniffing.** | `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, CSP in nginx ✅. |
| O4 | **Header injection** via `X-Request-ID`. | Accepted only if it parses as a UUID, otherwise regenerated ✅ (tested). |
| O5 | **Recon** via OpenAPI or docs in production. | Disabled when `env=production` ✅. |
| O6 | **Brute force / DoS on the API.** | Rate limits (⏳P6). |
| O8 | **Expensive unauthenticated intel endpoints** (`/api/intel/*`, NLP extract). | Read-only, lab-only (503 in hosted mode) ✅. Input caps: IOC 2 KB, CPE 512 B, text 20k, `max_hops` ≤ 4 ✅. Rate limits and auth (⏳P6). |
| O7 | **Hosted (Vercel) API is internet-facing**, not localhost-bound. | Hosted mode is forced by the entrypoint and dry-run only ✅ (tested). `env=production` defaults there, so OpenAPI is off ✅. HSTS/CSP via `vercel.json` ✅. Phase 0 exposes only health data (version, mode). **No mutating endpoint may be routed in hosted mode until auth lands (⏳P6).** |

### Enforcement layer (TB5)

| ID | Abuse case | Mitigations |
|---|---|---|
| E1 | **Self-lockout or mass quarantine** from a bug or poisoned intel. | DRY_RUN=true by default ✅, cannot be disabled in hosted mode ✅, logged loudly when disabled ✅. Protected hosts (gateway/broker/admin) and the broker IP are refused, as is anything outside `lab_cidr` ✅. Every quarantine has an expiry with auto-recovery (persistent job + 60 s sweep) ✅. Cap of `DSN_MAX_ACTIVE_QUARANTINES` concurrent quarantines ✅. Automatic quarantine only at CRITICAL ✅. Manual release via API/CLI ✅. All tested. |
| E2 | **Firewall state drift** after a crash, leaving devices quarantined forever or released early. | Desired state persisted in the DB ✅. At startup: release expired, then atomically replace the `inet dsn` table seeded with the desired set ✅ (tested against real nftables). Drift diff is audited ✅. Recovery jobs are persistent, with a sweep fallback ✅. |
| E3 | **Privilege creep:** the API process holds `NET_ADMIN`. | Base stack: no capabilities, dry-run only ✅. Gateway override: only `NET_ADMIN` + `NET_RAW`, granted as file capabilities to `nft`/`nmap`; the Python process runs as an unprivileged user ✅. Commands are argv lists with validated IPs, no shell ✅. Residual: host networking exposes the API on the host's interfaces if DSN_API_HOST is not loopback. |
| E4 | **Repudiation:** "who quarantined this?" | Append-only, hash-chained audit log with actor, action, outcome, reason and evidence for every quarantine, release, extension, refusal, reconcile, approval and status-node ack ✅. `GET /api/audit/verify` detects edits and deletions ✅ (tested). Residual: full DB-write access can rewrite the chain, so anchor the head hash externally. |
| E5 | **Spoofed status-node commands** make the LED show the wrong state, or replayed RECOVER hides a quarantine. | Commands are HMAC-SHA256-signed with a dedicated key over `id|ts|cmd|node_id|level|ttl` ✅. The firmware checks fields against a strict charset, verifies the signature in constant time, rejects messages with `|now − ts| > ttl` (ttl ≤ 300 s) and replayed ids, and refuses all commands until NTP has synced ✅ (18 host tests; a vector shared with the backend tests). Only the backend may publish to `dsn/cmd/#` ✅. The LED is informational and never the enforcement point ✅. Residual: the replay cache is in RAM, so after a reboot only the staleness window protects. |

### Data at rest (TB3)

| ID | Abuse case | Mitigations |
|---|---|---|
| S1 | **Database exfiltration** reveals device MACs. | MACs stored only as HMAC-SHA256 with a 32-byte or longer key ✅. The key lives only in env, never in the DB. |
| S2 | **HMAC key compromise.** | Rotating the key re-keys all device IDs. A re-keying procedure is documented in Phase 2 (⏳). |
| S3 | **Default datastore credentials.** | `NEO4J_AUTH` is required (compose fails without it). `make setup` generates random secrets ✅. Neo4j bound to localhost ✅. |

## 4. Residual risks / accepted

- A local attacker with root on the DSN host defeats all controls. Out of scope.
- MAC-based identity is spoofable (D1). It is mitigated by risk signals, not eliminated.
- Phase 0 has **no API authentication**. It is acceptable only because the API
  exposes read-only health data and binds to localhost. Auth must land before
  any mutating endpoint is exposed beyond localhost (tracked for P4/P6).
