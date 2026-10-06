# Fixtures

Inputs that let the whole platform run offline. The `MockAdapter` replays these
through the **real** feed parsers.

| File | Source | Kind | Built |
|---|---|---|---|
| `kev/kev.sample.json` | CISA KEV catalog (subset: 4 IoT/edge CVEs + Log4Shell) | real | `scripts/build_fixtures.py`, 2026-10-02 |
| `nvd/nvd.sample.json` | NVD CVE API 2.0 (5 CVEs, one not in KEV) | real | same |
| `attack/attack.sample.json` | MITRE ATT&CK enterprise + ICS bundles (IoT-relevant techniques, 7 software, 2 groups, their relationships, 1 revoked object) | real | same |
| `feodo/ipblocklist.sample.json` | Feodo Tracker IP blocklist (the live feed had 5 entries) | real | same |
| `urlhaus/urls_recent.sample.json` | URLhaus `/urls/recent/` shape per docs | **synthetic** | hand-written |
| `threatfox/get_iocs.sample.json` | ThreatFox `get_iocs` shape per docs, plus one unknown `ioc_type` | **synthetic** | hand-written |
| `darkweb/mentions.sample.json` | generic provider shape; defanged IOCs, noise, adversarial strings | **synthetic** | hand-written |
| `events/` | device/network events | – | Phase 2 / 7 |

Rebuild the real ones with `python scripts/build_fixtures.py [--nvd-api-key KEY]`.
Tests depend on their contents, so review the diff before committing.

## Rules

- No credentials or personal data.
- Synthetic IOCs use reserved ranges only: RFC 5737 IPs (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 IPv6 (`2001:db8::/32`) and
  RFC 2606 domains (`example.com/.net/.org`). Hashes are of harmless strings.
- Dark-web samples are invented text. No real forum content.

## Licensing / attribution

- **CISA KEV:** U.S. Government work, public domain.
- **NVD:** "This product uses data from the NVD API but is not endorsed or
  certified by the NVD."
- **MITRE ATT&CK®:** © The MITRE Corporation. Reproduced and distributed with
  permission under the ATT&CK Terms of Use.
- **Feodo Tracker (abuse.ch):** CC0.
