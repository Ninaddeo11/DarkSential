import { describe, expect, it } from "vitest";
import type { DsnEvent } from "../generated/events";
import type { Device } from "../api/types";
import { emptyState, fromSnapshot, LiveStore, MAX_EVENTS, reduce } from "./store";

const device = (node_id: string, extra: Partial<Device> = {}): Device => ({
  node_id,
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
  ...extra,
});

const risk = (seq: number, node: string, score: number, previous: number | null = null): DsnEvent => ({
  seq,
  type: "RISK_UPDATED",
  ts: "2026-10-08T00:00:00Z",
  node_id: node,
  payload: {
    score,
    level: score >= 70 ? "critical" : score >= 40 ? "medium" : "low",
    action: "monitor",
    explanation: "x",
    previous_score: previous,
    contributions: [],
  },
});

describe("reduce", () => {
  it("applies risk, quarantine and restore in seq order", () => {
    const s0 = fromSnapshot({ devices: [device("dev-a")], risks: [], quarantines: [], events: [] });
    const done: DsnEvent = {
      seq: 3,
      type: "QUARANTINE_COMPLETED",
      ts: "",
      node_id: "dev-a",
      payload: {
        ok: true, quarantine_id: 1, ip: "10.77.1.74", expires_at: null, dry_run: false,
        refused: null, error: null, command_id: null,
      },
    };
    const restored: DsnEvent = {
      seq: 4, type: "DEVICE_RESTORED", ts: "", node_id: "dev-a", payload: { quarantine_id: 1, ip: null },
    };
    // Out of order on purpose: the reducer sorts by seq.
    const s1 = reduce(s0, [restored, risk(2, "dev-a", 80), done], 1000);
    expect(s1.nodes["dev-a"]?.score).toBe(80);
    expect(s1.nodes["dev-a"]?.level).toBe("critical");
    expect(s1.nodes["dev-a"]?.quarantined).toBe(false); // restored (seq 4) after completed (seq 3)
    expect(s1.lastSeq).toBe(4);
    expect(s1.events.map((e) => e.seq)).toEqual([2, 3, 4]);
    expect(s0.nodes["dev-a"]?.score).toBeNull(); // inputs are not mutated
  });

  it("ignores replayed events (resume overlap)", () => {
    const s1 = reduce(emptyState(), [risk(1, "dev-a", 10), risk(2, "dev-a", 20)]);
    const s2 = reduce(s1, [risk(1, "dev-a", 99), risk(2, "dev-a", 99)]);
    expect(s2).toBe(s1); // nothing new: same object, no re-render
    expect(s2.nodes["dev-a"]?.score).toBe(20);
  });

  it("creates placeholders for unknown devices and caps the buffer", () => {
    const batch = Array.from({ length: MAX_EVENTS + 10 }, (_, i) => risk(i + 1, `dev-${i % 3}`, i % 100));
    const s = reduce(emptyState(), batch);
    expect(Object.keys(s.nodes).sort()).toEqual(["dev-0", "dev-1", "dev-2"]);
    expect(s.events).toHaveLength(MAX_EVENTS);
    expect(s.events[0]?.seq).toBe(11);
    expect(s.received).toBe(MAX_EVENTS + 10);
  });

  it("restores quarantine state and scores from the snapshot", () => {
    const s = fromSnapshot({
      devices: [device("dev-a"), device("dev-b")],
      risks: [{ node_id: "dev-a", score: 42.8, level: "medium" } as never],
      quarantines: [{ node_id: "dev-b", status: "active" } as never],
      events: [risk(7, "dev-a", 42.8)],
    });
    expect(s.nodes["dev-a"]?.score).toBe(42.8);
    expect(s.nodes["dev-b"]?.quarantined).toBe(true);
    expect(s.lastSeq).toBe(7);
  });
});

describe("LiveStore", () => {
  it("coalesces bursts into one update per frame", () => {
    const frames: Array<() => void> = [];
    const store = new LiveStore((cb) => frames.push(cb));
    let renders = 0;
    store.subscribe(() => renders++);
    for (let i = 1; i <= 300; i++) store.ingest([risk(i, "dev-a", i % 100)]);
    expect(frames).toHaveLength(1); // 300 socket messages -> one scheduled frame
    frames[0]?.();
    expect(renders).toBe(1);
    expect(store.getState().lastSeq).toBe(300);
  });

  it("applies a 10k-event burst quickly (measured)", () => {
    const store = new LiveStore((cb) => cb());
    const nodes = 200;
    const batch = Array.from({ length: 10_000 }, (_, i) => risk(i + 1, `dev-${i % nodes}`, i % 100));
    const t0 = performance.now();
    for (let i = 0; i < batch.length; i += 1000) store.ingest(batch.slice(i, i + 1000));
    const ms = performance.now() - t0;
    console.info(`10k events over ${nodes} devices applied in ${ms.toFixed(1)} ms`);
    expect(store.getState().lastSeq).toBe(10_000);
    expect(Object.keys(store.getState().nodes)).toHaveLength(nodes);
    expect(ms).toBeLessThan(1000); // generous bound; the measured value is printed above
  });
});
