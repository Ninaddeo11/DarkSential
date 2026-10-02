# Fixtures

Recorded or synthetic inputs that let the whole platform run offline. `MockAdapter`s replay these.

| Dir | Contents | Phase |
|---|---|---|
| `kev/` | CISA KEV catalog sample | 1 |
| `stix/` | STIX 2.1 bundles (ATT&CK subset, abuse.ch-derived indicators) | 1 |
| `darkweb/` | Synthetic dark-web mention samples, including adversarial/noisy text | 1 |
| `events/` | pcap-derived / simulated device events | 2, 7 |

Rules: no real credentials or personal data. Dark-web samples are synthetic,
and each one states its provenance in its own metadata.
