// Live dashboard state. `reduce` is a pure function (unit-tested); the store
// wraps it with batched, frame-coalesced notifications: however many events
// arrive, React re-renders at most once per animation frame.
import type { DsnEvent } from "../generated/events";
import type { Device, Quarantine, RiskDecision, RiskLevel } from "../api/types";

export const MAX_EVENTS = 5000;

export interface NodeState {
  device: Device;
  score: number | null;
  level: RiskLevel | null;
  quarantined: boolean;
  lastEventSeq: number;
  /** ms timestamp of the last noteworthy change (drives the pulse animation). */
  flashAt: number;
}

export interface LiveState {
  nodes: Record<string, NodeState>;
  events: DsnEvent[]; // newest last, at most MAX_EVENTS
  lastSeq: number;
  received: number; // events applied since load (for the rate meter)
}

export const emptyState = (): LiveState => ({ nodes: {}, events: [], lastSeq: 0, received: 0 });

export interface Snapshot {
  devices: Device[];
  risks: RiskDecision[];
  quarantines: Quarantine[];
  events: DsnEvent[];
}

export function fromSnapshot(snap: Snapshot): LiveState {
  const nodes: Record<string, NodeState> = {};
  for (const device of snap.devices) {
    nodes[device.node_id] = {
      device,
      score: null,
      level: null,
      quarantined: false,
      lastEventSeq: 0,
      flashAt: 0,
    };
  }
  for (const r of snap.risks) {
    const n = nodes[r.node_id];
    if (n) {
      n.score = r.score;
      n.level = r.level;
    }
  }
  for (const q of snap.quarantines) {
    const n = nodes[q.node_id];
    if (n && q.status === "active") n.quarantined = true;
  }
  const events = snap.events.slice(-MAX_EVENTS);
  const lastSeq = events.reduce((m, e) => Math.max(m, e.seq), 0);
  return { nodes, events, lastSeq, received: 0 };
}

function placeholder(nodeId: string): NodeState {
  return {
    device: {
      node_id: nodeId,
      trust: "unknown",
      vendor: null,
      oui: null,
      randomized_mac: false,
      ip: null,
      hostname: null,
      services: [],
      cpes: [],
      sources: [],
      attributes: {},
      first_seen: "",
      last_seen: "",
    },
    score: null,
    level: null,
    quarantined: false,
    lastEventSeq: 0,
    flashAt: 0,
  };
}

/** Apply a batch of events. Duplicates (seq <= lastSeq) are ignored, so a replay
 * after reconnect can overlap what the client already has. */
export function reduce(state: LiveState, batch: DsnEvent[], now = Date.now()): LiveState {
  const fresh = batch.filter((e) => e.seq > state.lastSeq).sort((a, b) => a.seq - b.seq);
  if (fresh.length === 0) return state;
  const nodes = { ...state.nodes };
  const touch = (id: string): NodeState => {
    const current = nodes[id] ?? placeholder(id);
    const copy = { ...current, device: { ...current.device } };
    nodes[id] = copy;
    return copy;
  };
  for (const e of fresh) {
    if (!e.node_id) continue;
    const n = touch(e.node_id);
    n.lastEventSeq = e.seq;
    switch (e.type) {
      case "DEVICE_CONNECTED":
        n.device.trust = e.payload.trust as Device["trust"];
        n.device.vendor = e.payload.vendor ?? n.device.vendor;
        n.device.ip = e.payload.ip ?? n.device.ip;
        if (!n.device.sources.includes(e.payload.source)) {
          n.device.sources = [...n.device.sources, e.payload.source];
        }
        n.flashAt = now;
        break;
      case "DEVICE_PROFILED":
        n.device.vendor = e.payload.vendor ?? n.device.vendor;
        n.device.hostname = e.payload.hostname ?? n.device.hostname;
        n.device.cpes = e.payload.cpes;
        break;
      case "RISK_UPDATED":
        n.score = e.payload.score;
        n.level = e.payload.level;
        if (e.payload.previous_score === null || e.payload.score > e.payload.previous_score) {
          n.flashAt = now;
        }
        break;
      case "ANOMALY_DETECTED":
      case "THREAT_CORRELATED":
        n.flashAt = now;
        break;
      case "QUARANTINE_COMPLETED":
        if (e.payload.ok) n.quarantined = true;
        n.flashAt = now;
        break;
      case "DEVICE_RESTORED":
        n.quarantined = false;
        n.flashAt = now;
        break;
      case "QUARANTINE_STARTED":
      case "RECOVERY_STARTED":
        break;
    }
  }
  const events = state.events.concat(fresh);
  return {
    nodes,
    events: events.length > MAX_EVENTS ? events.slice(events.length - MAX_EVENTS) : events,
    lastSeq: fresh.at(-1)?.seq ?? state.lastSeq,
    received: state.received + fresh.length,
  };
}

type Listener = () => void;

export class LiveStore {
  private state: LiveState = emptyState();
  private listeners = new Set<Listener>();
  private pending: DsnEvent[] = [];
  private scheduled = false;

  constructor(private readonly schedule: (cb: () => void) => void = defaultSchedule) {}

  getState = (): LiveState => this.state;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  reset(snapshot: Snapshot): void {
    this.pending = [];
    this.state = fromSnapshot(snapshot);
    this.emit();
  }

  /** Queue events; they are applied together on the next frame. */
  ingest(batch: DsnEvent[]): void {
    this.pending.push(...batch);
    if (this.scheduled) return;
    this.scheduled = true;
    this.schedule(() => {
      this.scheduled = false;
      const batchNow = this.pending;
      this.pending = [];
      const next = reduce(this.state, batchNow);
      if (next !== this.state) {
        this.state = next;
        this.emit();
      }
    });
  }

  /** Replace one device's record (after a REST refresh). */
  upsertDevice(device: Device): void {
    const current = this.state.nodes[device.node_id];
    const base = current ?? placeholder(device.node_id);
    this.state = {
      ...this.state,
      nodes: { ...this.state.nodes, [device.node_id]: { ...base, device } },
    };
    this.emit();
  }

  private emit(): void {
    for (const l of this.listeners) l();
  }
}

function defaultSchedule(cb: () => void): void {
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(cb);
  else setTimeout(cb, 16);
}
