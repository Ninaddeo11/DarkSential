// Simulated investigation for the hosted demo. Every entity here is fictional:
// "138.987.22.22" is not a valid IPv4 address (987 > 255), so it can never name
// a real host; wallet strings contain "sim" (not in the bech32 alphabet), domains
// use the reserved .invalid TLD, the ASN is from the private range, and the
// consignment position is in international waters. Nothing is fetched or sent.
import type { PathStep, RelatedThreat } from "../api/types";

export const SIM_IOC = "138.987.22.22";

export function isSimulatedIoc(value: string): boolean {
  return value.trim() === SIM_IOC;
}

interface Entity {
  id: string;
  label: string; // graph class: Malware, Infrastructure, ThreatActor, Ledger, Consignment
  name: string;
}

const E = {
  ip: { id: "sim:indicator:138.987.22.22", label: "Indicator", name: SIM_IOC },
  mirai: { id: "sim:malware:mirai-okiru", label: "Malware", name: "Mirai (Okiru variant)" },
  mozi: { id: "sim:malware:mozi", label: "Malware", name: "Mozi P2P botnet" },
  miner: { id: "sim:malware:xmrig-miner", label: "Malware", name: "XMRig-based coinminer" },
  stealer: { id: "sim:malware:redline", label: "Malware", name: "RedLine Stealer" },
  c2: { id: "sim:infra:c2-onion", label: "Infrastructure", name: "C2 panel k7sim…q3ad.onion" },
  pool: { id: "sim:infra:xmr-pool", label: "Infrastructure", name: "xmr-pool.nexus-sim.invalid:3333" },
  asn: { id: "sim:infra:as64512", label: "Infrastructure", name: "AS64512 bulletproof hosting" },
  actor: { id: "sim:actor:kestrel", label: "ThreatActor", name: "Kestrel Syndicate" },
  market: { id: "sim:infra:market-a1187", label: "Infrastructure", name: "Marketplace listing A-1187" },
  xmrWallet: { id: "sim:ledger:xmr-payout", label: "Ledger", name: "XMR payout wallet 4Asim…9Qx" },
  btcDrain: { id: "sim:ledger:btc-drain", label: "Ledger", name: "BTC wallet bc1qsim…7dk2" },
  mixer: { id: "sim:ledger:coinjoin", label: "Ledger", name: "CoinJoin mixer round" },
  escrow: { id: "sim:ledger:btc-escrow", label: "Ledger", name: "BTC escrow bc1qsim…e5cr" },
  consignment: {
    id: "sim:consignment:nx-0427",
    label: "Consignment",
    name: "Narcotics consignment NX-0427",
  },
} satisfies Record<string, Entity>;

type Hop = [Entity, string | null];

function path(...hops: Hop[]): PathStep[] {
  return hops.map(([e, via]) => ({ node_id: e.id, label: e.label, name: e.name, via }));
}

const DARKWEB = ["simulation", "darkweb"];

function threat(p: PathStep[], confidence: number, sources = ["simulation"]): RelatedThreat {
  const end = p[p.length - 1]!;
  return {
    threat_id: end.node_id,
    label: end.label,
    name: end.name,
    external_id: end.node_id.replace(/^sim:/, "SIM/"),
    hops: p.length - 1,
    confidence,
    sources,
    indicator_id: E.ip.id,
    indicator_stale: false,
    path: p,
  };
}

/** Evidence paths from the indicator, in the same shape the threat graph returns. */
export function simulatedThreats(): RelatedThreat[] {
  const ip: Hop = [E.ip, null];
  return [
    threat(path(ip, [E.c2, "hosts C2 for"], [E.mirai, "controls"]), 0.93),
    threat(path(ip, [E.mozi, "distributes"]), 0.88),
    threat(path(ip, [E.miner, "serves payload"]), 0.91),
    threat(path(ip, [E.stealer, "exfiltration endpoint for"]), 0.86),
    threat(path(ip, [E.miner, "serves payload"], [E.pool, "mines to"], [E.xmrWallet, "pays out to"]), 0.84),
    threat(
      path(
        ip,
        [E.stealer, "exfiltration endpoint for"],
        [E.btcDrain, "drains wallets to"],
        [E.mixer, "mixed via"],
        [E.escrow, "settles to"],
      ),
      0.79,
      DARKWEB,
    ),
    threat(path(ip, [E.asn, "announced by"], [E.actor, "operated by"]), 0.77, DARKWEB),
    threat(path(ip, [E.asn, "announced by"], [E.actor, "operated by"], [E.market, "runs"]), 0.81, DARKWEB),
    threat(
      path(
        ip,
        [E.asn, "announced by"],
        [E.actor, "operated by"],
        [E.market, "runs"],
        [E.escrow, "escrow via"],
        [E.consignment, "pays for"],
      ),
      0.74,
      DARKWEB,
    ),
  ];
}

/** Object counts of the simulated graph, by class (the hosted "graph inventory"). */
export function simulatedCounts(): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const e of Object.values(E)) counts[e.label] = (counts[e.label] ?? 0) + 1;
  counts.relationships = 15;
  return counts;
}

// --- investigation report ------------------------------------------------------

export interface SimMalware {
  family: string;
  type: string;
  role: string;
  techniques: string[];
  firstSeen: string;
}

export interface SimTransfer {
  ts: string;
  asset: "XMR" | "BTC";
  amount: number;
  from: string;
  to: string;
  note: string;
  tx: string;
}

export const REPORT = {
  ioc: SIM_IOC,
  verdict: "Malicious",
  score: 96,
  firstSeen: "2026-09-21T03:14:00Z",
  lastSeen: "2026-10-08T22:41:00Z",
  hosting: "AS64512 bulletproof hosting (private ASN, simulated)",
  actor: "Kestrel Syndicate (fictional)",
  malware: [
    {
      family: "Mirai (Okiru variant)",
      type: "IoT botnet",
      role: "C2 panel on an onion service; floods and Telnet brute force",
      techniques: ["T1498", "T1110"],
      firstSeen: "2026-09-21",
    },
    {
      family: "Mozi",
      type: "P2P IoT botnet",
      role: "Payload distribution to routers and DVRs",
      techniques: ["T1110", "T1105"],
      firstSeen: "2026-09-24",
    },
    {
      family: "XMRig-based coinminer",
      type: "Cryptojacking",
      role: "Mines Monero on compromised devices",
      techniques: ["T1496"],
      firstSeen: "2026-09-27",
    },
    {
      family: "RedLine Stealer",
      type: "Infostealer",
      role: "Steals browser credentials and wallet files",
      techniques: ["T1555", "T1005"],
      firstSeen: "2026-10-02",
    },
  ] satisfies SimMalware[],
  transfers: [
    { ts: "2026-10-01T04:10:00Z", asset: "XMR", amount: 1.82, from: "xmr-pool (sim)", to: "4Asim…9Qx", note: "Mining payout", tx: "59cd53c195a35b2c6f75d76067faeab1ca303b2780194e74d1d57a888dc01fee" },
    { ts: "2026-10-03T04:12:00Z", asset: "XMR", amount: 2.07, from: "xmr-pool (sim)", to: "4Asim…9Qx", note: "Mining payout", tx: "afcc93ff720835d8363db12095d1ed4a9e318ee71e6c0bdbc8a624596cdeb894" },
    { ts: "2026-10-04T19:55:00Z", asset: "BTC", amount: 0.31, from: "victim wallets (stealer)", to: "bc1qsim…7dk2", note: "Drained by RedLine", tx: "8b641468c84c38673d0c1169870a53e0e056ac52a9c1c0d46df7de8b9f4a158b" },
    { ts: "2026-10-05T02:31:00Z", asset: "BTC", amount: 0.27, from: "victim wallets (stealer)", to: "bc1qsim…7dk2", note: "Drained by RedLine", tx: "95550359fdf154b3513eb89f49c37eb20724b276668dfc5ee41ad966d399a3f3" },
    { ts: "2026-10-05T09:02:00Z", asset: "BTC", amount: 0.58, from: "bc1qsim…7dk2", to: "CoinJoin round", note: "Mixing", tx: "43dd26748586464aa1f8fe3c8be7f032ee56e5c67ae8974e6e7863369c2ecc17" },
    { ts: "2026-10-06T11:47:00Z", asset: "BTC", amount: 0.55, from: "CoinJoin round", to: "bc1qsim…e5cr", note: "Mixer output to escrow", tx: "47e290195474d6edca42baab387fdb2fa43cc70eb17af440c89d15bd7cf45378" },
    { ts: "2026-10-06T16:20:00Z", asset: "BTC", amount: 0.4, from: "Marketplace A-1187 buyer", to: "bc1qsim…e5cr", note: "Listing escrow", tx: "e75754ea099e350bb0f11a6286d82b793ff7aaa29b32b23e077092fff0fdc8e6" },
    { ts: "2026-10-07T08:05:00Z", asset: "BTC", amount: 0.84, from: "bc1qsim…e5cr", to: "supplier (NX-0427)", note: "Payment for consignment", tx: "0403fd5cb44809adcb1e777157e534ebda6eaa0859ac9eb98fd939d536f9bad4" },
  ] satisfies SimTransfer[],
  consignment: {
    id: "NX-0427",
    lat: 18.5204,
    lon: 66.0412,
    region: "Arabian Sea (international waters)",
    status: "In transit",
    lastFix: "2026-10-08T21:30:00Z",
    payment: "0.84 BTC (tx 0403fd5c…f9bad4)",
    listing: "Marketplace listing A-1187",
  },
};

// --- devices in active communication with the indicator ------------------------
// Addresses are from the RFC 5737 documentation ranges (never routed on the
// internet); locations are city centres.

export interface SimCommDevice {
  id: string;
  name: string;
  country: string;
  countryId: string; // ISO 3166 numeric, as in world-atlas
  city: string;
  lat: number;
  lon: number;
  ip: string;
  type: string;
  channel: string;
  role: string;
  /** Packets per minute to/from the indicator (drives the live counters). */
  ppm: number;
}

export const COMMS: SimCommDevice[] = [
  {
    id: "sim:dev:ru-01",
    name: "Device 1",
    country: "Russia",
    countryId: "643",
    city: "Moscow",
    lat: 55.7558,
    lon: 37.6173,
    ip: "203.0.113.41",
    type: "Operator workstation (Windows 11)",
    channel: "TLS 443 → C2 panel",
    role: "Botnet operator console: issues Mirai attack and miner commands",
    ppm: 142,
  },
  {
    id: "sim:dev:lk-02",
    name: "Device 2",
    country: "Sri Lanka",
    countryId: "144",
    city: "Colombo",
    lat: 6.9271,
    lon: 79.8612,
    ip: "198.51.100.17",
    type: "Android handset",
    channel: "Tor obfs4 9001 → marketplace",
    role: "Marketplace session and BTC escrow approvals for NX-0427",
    ppm: 37,
  },
  {
    id: "sim:dev:lk-03",
    name: "Device 3",
    country: "Sri Lanka",
    countryId: "144",
    city: "Kandy",
    lat: 7.2906,
    lon: 80.6337,
    ip: "198.51.100.23",
    type: "Compromised home router",
    channel: "MQTT 1883 / Telnet 23",
    role: "Mozi relay node and XMRig miner reporting to the pool",
    ppm: 268,
  },
];

export function formatCoordinate(lat: number, lon: number): string {
  const ns = lat >= 0 ? "N" : "S";
  const ew = lon >= 0 ? "E" : "W";
  return `${Math.abs(lat).toFixed(4)}° ${ns}, ${Math.abs(lon).toFixed(4)}° ${ew}`;
}
