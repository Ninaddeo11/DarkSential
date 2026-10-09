// Deterministic simulated scenario for any IPv4 address (hosted demo).
// Seeded from the address, so one IP always shows the same result. Synthetic by
// construction: device addresses come from the RFC 5737 documentation ranges,
// subdomains are random DGA-style labels (10-12 random characters, so they
// don't name real registered domains), and the ASN is from the private range.
import type { PathStep, RelatedThreat } from "../api/types";
import {
  HANDCRAFTED,
  SIM_IOC,
  type Scenario,
  type SimCommDevice,
  type SimMalware,
  type SimSubdomain,
} from "./scenario";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function isIpLike(value: string): boolean {
  return IPV4.test(value.trim());
}

/** The scenario for an indicator, or null when it isn't simulated.
 * Lab: only SIM_IOC (real lookups stay real). Hosted: any IPv4 address. */
export function scenarioFor(ioc: string, hosted: boolean): Scenario | null {
  const value = ioc.trim();
  if (value === SIM_IOC) return HANDCRAFTED;
  if (!hosted || !isIpLike(value)) return null;
  let s = cache.get(value);
  if (!s) {
    s = generateScenario(value);
    cache.set(value, s);
  }
  return s;
}

const cache = new Map<string, Scenario>();

// --- seeded randomness ---------------------------------------------------------

function fnv1a(text: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Rand {
  private next: () => number;
  constructor(seed: string) {
    this.next = mulberry32(fnv1a(seed));
  }
  float(): number {
    return this.next();
  }
  int(lo: number, hi: number): number {
    return lo + Math.floor(this.next() * (hi - lo + 1));
  }
  pick<T>(items: readonly T[]): T {
    return items[Math.floor(this.next() * items.length)]!;
  }
  sample<T>(items: readonly T[], n: number): T[] {
    const pool = [...items];
    const out: T[] = [];
    while (out.length < n && pool.length) out.push(pool.splice(Math.floor(this.next() * pool.length), 1)[0]!);
    return out;
  }
  label(len: number): string {
    const chars = [..."abcdefghijklmnopqrstuvwxyz0123456789"];
    let s = this.pick(chars.slice(0, 26)); // DNS labels here start with a letter
    while (s.length < len) s += this.pick(chars);
    return s;
  }
}

// --- pools ---------------------------------------------------------------------

const MALWARE: SimMalware[] = [
  { family: "Mirai", type: "IoT botnet", role: "Telnet brute force and DDoS floods", techniques: ["T1110", "T1498"], firstSeen: "" },
  { family: "Gafgyt (Bashlite)", type: "IoT botnet", role: "Scans for weak IoT credentials, floods targets", techniques: ["T1110", "T1498"], firstSeen: "" },
  { family: "Mozi", type: "P2P IoT botnet", role: "Payload distribution over a DHT network", techniques: ["T1110", "T1105"], firstSeen: "" },
  { family: "Emotet", type: "Loader", role: "Malspam loader dropping follow-on payloads", techniques: ["T1566", "T1059"], firstSeen: "" },
  { family: "QakBot", type: "Banking trojan", role: "Credential theft and lateral movement", techniques: ["T1566", "T1055"], firstSeen: "" },
  { family: "Agent Tesla", type: "Infostealer", role: "Keylogging and credential exfiltration", techniques: ["T1056", "T1555"], firstSeen: "" },
  { family: "RedLine Stealer", type: "Infostealer", role: "Steals browser credentials and wallet files", techniques: ["T1555", "T1005"], firstSeen: "" },
  { family: "LokiBot", type: "Infostealer", role: "Harvests credentials over HTTP POST", techniques: ["T1555", "T1041"], firstSeen: "" },
  { family: "Formbook", type: "Infostealer", role: "Form grabbing and screenshots", techniques: ["T1056", "T1113"], firstSeen: "" },
  { family: "AsyncRAT", type: "Remote access trojan", role: "Remote control over an encrypted channel", techniques: ["T1071", "T1105"], firstSeen: "" },
  { family: "Remcos", type: "Remote access trojan", role: "Remote desktop, keylogging and screenshots", techniques: ["T1219", "T1113"], firstSeen: "" },
  { family: "Cobalt Strike beacon", type: "Post-exploitation C2", role: "Beaconing implant for hands-on-keyboard access", techniques: ["T1071", "T1055"], firstSeen: "" },
  { family: "XMRig-based coinminer", type: "Cryptojacking", role: "Mines Monero on compromised hosts", techniques: ["T1496"], firstSeen: "" },
  { family: "LockBit", type: "Ransomware", role: "Encrypts files and deletes shadow copies", techniques: ["T1486", "T1490"], firstSeen: "" },
];

const COUNTRIES = [
  { country: "Russia", countryId: "643", city: "Moscow", lat: 55.7558, lon: 37.6173 },
  { country: "Sri Lanka", countryId: "144", city: "Colombo", lat: 6.9271, lon: 79.8612 },
  { country: "China", countryId: "156", city: "Shanghai", lat: 31.2304, lon: 121.4737 },
  { country: "Iran", countryId: "364", city: "Tehran", lat: 35.6892, lon: 51.389 },
  { country: "Brazil", countryId: "076", city: "São Paulo", lat: -23.5505, lon: -46.6333 },
  { country: "Nigeria", countryId: "566", city: "Lagos", lat: 6.5244, lon: 3.3792 },
  { country: "Romania", countryId: "642", city: "Bucharest", lat: 44.4268, lon: 26.1025 },
  { country: "Ukraine", countryId: "804", city: "Kyiv", lat: 50.4501, lon: 30.5234 },
  { country: "Netherlands", countryId: "528", city: "Amsterdam", lat: 52.3676, lon: 4.9041 },
  { country: "Germany", countryId: "276", city: "Frankfurt", lat: 50.1109, lon: 8.6821 },
  { country: "United States", countryId: "840", city: "Ashburn", lat: 39.0438, lon: -77.4874 },
  { country: "Vietnam", countryId: "704", city: "Hanoi", lat: 21.0278, lon: 105.8342 },
  { country: "India", countryId: "356", city: "Mumbai", lat: 19.076, lon: 72.8777 },
  { country: "Turkey", countryId: "792", city: "Istanbul", lat: 41.0082, lon: 28.9784 },
  { country: "Indonesia", countryId: "360", city: "Jakarta", lat: -6.2088, lon: 106.8456 },
  { country: "South Africa", countryId: "710", city: "Johannesburg", lat: -26.2041, lon: 28.0473 },
  { country: "Kazakhstan", countryId: "398", city: "Almaty", lat: 43.222, lon: 76.8512 },
  { country: "Pakistan", countryId: "586", city: "Karachi", lat: 24.8607, lon: 67.0011 },
  { country: "Bangladesh", countryId: "050", city: "Dhaka", lat: 23.8103, lon: 90.4125 },
  { country: "Thailand", countryId: "764", city: "Bangkok", lat: 13.7563, lon: 100.5018 },
  { country: "Malaysia", countryId: "458", city: "Kuala Lumpur", lat: 3.139, lon: 101.6869 },
  { country: "Egypt", countryId: "818", city: "Cairo", lat: 30.0444, lon: 31.2357 },
  { country: "Mexico", countryId: "484", city: "Mexico City", lat: 19.4326, lon: -99.1332 },
  { country: "Poland", countryId: "616", city: "Warsaw", lat: 52.2297, lon: 21.0122 },
  { country: "France", countryId: "250", city: "Paris", lat: 48.8566, lon: 2.3522 },
  { country: "Japan", countryId: "392", city: "Tokyo", lat: 35.6762, lon: 139.6503 },
  { country: "South Korea", countryId: "410", city: "Seoul", lat: 37.5665, lon: 126.978 },
  { country: "Philippines", countryId: "608", city: "Manila", lat: 14.5995, lon: 120.9842 },
  { country: "Kenya", countryId: "404", city: "Nairobi", lat: -1.2921, lon: 36.8219 },
  { country: "Colombia", countryId: "170", city: "Bogotá", lat: 4.711, lon: -74.0721 },
];

// Open-sea anchor points for the indicator: its hosting location is masked, and
// drawing it over land would imply a country.
const OCEAN: [number, number][] = [
  [-35, 22], [-28, -12], [-45, 40], [-140, 12], [-120, -20], [160, 25], [150, -10],
  [62, 11], [70, -8], [88, 12], [114, 13], [18, 35], [5, 38], [33, 33], [-90, 22], [-20, 55],
];

const TLDS = ["top", "xyz", "info", "online", "site", "shop", "biz", "cc", "live", "click"];
const PREFIXES = ["update", "cdn", "api", "secure", "login", "portal", "dl", "files", "sync", "auth", "static", "gate", "panel", "mail", "img"];
const DEVICE_TYPES = [
  "Linux VPS", "Windows 10 workstation", "Windows 11 workstation", "Android handset",
  "Compromised home router", "IP camera (DVR)", "NAS appliance", "Raspberry Pi", "macOS laptop",
];
const CHANNELS = [
  "TLS 443 → C2", "HTTP 8080 beacon", "MQTT 1883", "Telnet 23", "Tor obfs4 9001",
  "DNS tunnel 53", "SSH 22", "IRC 6667", "HTTPS 8443 → panel",
];
const DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"];

// --- generator -----------------------------------------------------------------

const day = (base: Date, back: number, rand: Rand) =>
  new Date(base.getTime() - back * 86_400_000 - rand.int(0, 86_399) * 1000).toISOString();

export function generateScenario(ip: string, today = new Date()): Scenario {
  const r = new Rand(ip);
  const malware = r.sample(MALWARE, r.int(2, 4)).map((m) => ({ ...m, firstSeen: day(today, r.int(8, 45), r).slice(0, 10) }));
  const subdomains: SimSubdomain[] = Array.from({ length: r.int(3, 5) }, (_, i) => ({
    host: `${r.pick(PREFIXES)}.${r.label(r.int(10, 12))}.${r.pick(TLDS)}`,
    malware: malware[i % malware.length]!.family,
    firstSeen: day(today, r.int(1, 40), r),
  }));

  const comms: SimCommDevice[] = r.sample(COUNTRIES, 3).map((c, i) => {
    const sub = subdomains[i % subdomains.length]!;
    const role = r.pick([
      `Beacons to ${sub.host} (${sub.malware})`,
      `Pulls ${sub.malware} payloads from ${sub.host}`,
      `Exfiltrates data through ${sub.host}`,
      `Relays ${sub.malware} commands for the operator`,
    ]);
    return {
      id: `sim:dev:${ip}:${i}`,
      name: `Device ${i + 1}`,
      ...c,
      ip: `${r.pick(DOC_NETS)}.${r.int(2, 254)}`,
      type: r.pick(DEVICE_TYPES),
      channel: r.pick(CHANNELS),
      role,
      ppm: r.int(20, 300),
    };
  });

  // Map view: the devices plus the nearest open-sea anchor for the indicator.
  const cx = comms.reduce((s, d) => s + d.lon, 0) / comms.length;
  const cy = comms.reduce((s, d) => s + d.lat, 0) / comms.length;
  // Nearest sea anchor to the devices' centre that keeps clear of every device.
  const clear = OCEAN.filter(([x, y]) => comms.every((d) => Math.hypot(d.lon - x, d.lat - y) >= 15));
  const hub = [...(clear.length ? clear : OCEAN)].sort(
    (a, b) => Math.hypot(a[0] - cx, a[1] - cy) - Math.hypot(b[0] - cx, b[1] - cy),
  )[0]!;
  const lons = [...comms.map((d) => d.lon), hub[0]];
  const lats = [...comms.map((d) => d.lat), hub[1]];
  const extent = padExtent(Math.min(...lons), Math.min(...lats), Math.max(...lons), Math.max(...lats));

  const ipNode: PathStep = { node_id: `sim:indicator:${ip}`, label: "Indicator", name: ip, via: null };
  const asn = `AS${r.int(64512, 65534)}`;
  const asnNode: PathStep = { node_id: `sim:infra:${asn}`, label: "Infrastructure", name: `${asn} hosting`, via: "announced by" };
  const threats: RelatedThreat[] = subdomains.map((s) => {
    const path: PathStep[] = [
      ipNode,
      { node_id: `sim:domain:${s.host}`, label: "Infrastructure", name: s.host, via: "resolves from" },
      { node_id: `sim:malware:${s.malware}`, label: "Malware", name: s.malware, via: "serves" },
    ];
    return {
      threat_id: `sim:domain:${s.host}>malware`,
      label: "Malware",
      name: s.malware,
      external_id: s.host,
      hops: 2,
      confidence: Math.round((0.62 + r.float() * 0.33) * 100) / 100,
      sources: ["simulation"],
      indicator_id: ipNode.node_id,
      indicator_stale: false,
      path,
    };
  });
  threats.push({
    threat_id: asnNode.node_id,
    label: "Infrastructure",
    name: asnNode.name,
    external_id: asn,
    hops: 1,
    confidence: 0.7,
    sources: ["simulation"],
    indicator_id: ipNode.node_id,
    indicator_stale: false,
    path: [ipNode, asnNode],
  });

  const seen = subdomains.map((s) => s.firstSeen).sort();
  return {
    ioc: ip,
    threats,
    counts: {
      Indicator: 1,
      Infrastructure: subdomains.length + 1,
      Malware: malware.length,
      relationships: subdomains.length * 2 + 1,
    },
    report: {
      ioc: ip,
      verdict: "Malicious",
      score: r.int(74, 97),
      firstSeen: seen[0]!,
      lastSeen: day(today, 0, r),
      hosting: `${asn} hosting (private ASN)`,
      actor: null,
      malware,
      subdomains,
      transfers: [],
      consignment: null,
    },
    comms,
    map: { extent, hub, countryLabels: [] },
  };
}

/** Pad a lon/lat box and give it a minimum span, so the map has context. */
function padExtent(x0: number, y0: number, x1: number, y1: number): [[number, number], [number, number]] {
  const minLon = 50;
  const minLat = 30;
  let [a, b, c, d] = [x0 - 10, y0 - 8, x1 + 10, y1 + 8];
  if (c - a < minLon) [a, c] = [(a + c) / 2 - minLon / 2, (a + c) / 2 + minLon / 2];
  if (d - b < minLat) [b, d] = [(b + d) / 2 - minLat / 2, (b + d) / 2 + minLat / 2];
  return [[Math.max(-180, a), Math.max(-60, b)], [Math.min(180, c), Math.min(80, d)]];
}
