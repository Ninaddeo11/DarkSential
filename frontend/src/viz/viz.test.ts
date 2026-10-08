import { describe, expect, it } from "vitest";
import { makeNode, seed, step } from "./layout";
import { shapBars, waterfall } from "./waterfall";
import { summarize } from "../components/Timeline";

describe("waterfall", () => {
  it("stacks contributions largest-first and ends at the score", () => {
    const bars = waterfall([
      { factor: "unknown_device", value: 1, weight: 0.1, contribution: 10 },
      { factor: "threat_intel", value: 0.48, weight: 0.35, contribution: 16.8 },
      { factor: "protocol_anomaly", value: 0, weight: 0.1, contribution: 0 },
      { factor: "rate_anomaly", value: 0.8, weight: 0.2, contribution: 16 },
    ]);
    expect(bars.map((b) => b.factor)).toEqual([
      "threat_intel",
      "rate_anomaly",
      "unknown_device",
      "protocol_anomaly",
    ]);
    expect(bars[0]?.start).toBe(0);
    for (let i = 1; i < bars.length; i++) expect(bars[i]?.start).toBe(bars[i - 1]?.end);
    expect(bars.at(-1)?.end).toBeCloseTo(42.8, 10);
  });

  it("orders SHAP values by absolute impact", () => {
    expect(shapBars({ a: 0.1, b: -0.9, c: 0.5 }).map((b) => b.feature)).toEqual(["b", "c", "a"]);
  });
});

describe("layout", () => {
  it("seeds deterministically", () => {
    expect(seed("dev-1")).toEqual(seed("dev-1"));
    expect(seed("dev-1")).not.toEqual(seed("dev-2"));
  });

  it("settles, keeps the hub fixed and separates nodes", () => {
    const hub = makeNode("hub", [0, 0, 0]);
    const nodes = [hub, ...Array.from({ length: 20 }, (_, i) => makeNode(`dev-${i}`))];
    const edges = nodes.slice(1).map((n) => ["hub", n.id] as [string, string]);
    let energy = Infinity;
    let steps = 0;
    while (energy > 1e-4 && steps < 2000) {
      energy = step(nodes, edges);
      steps++;
    }
    expect(energy).toBeLessThanOrEqual(1e-4);
    expect(hub.pos).toEqual([0, 0, 0]);
    let closest = Infinity;
    for (let i = 1; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i]!.pos;
        const b = nodes[j]!.pos;
        closest = Math.min(closest, Math.hypot(a[0] - b[0], a[1] - b[1], a[2] - b[2]));
      }
    }
    expect(closest).toBeGreaterThan(0.8); // no overlapping spheres
  });
});

describe("timeline summaries", () => {
  it("describes each event type", () => {
    expect(
      summarize({
        seq: 1,
        type: "QUARANTINE_COMPLETED",
        ts: "",
        node_id: "dev-a",
        payload: {
          ok: false, quarantine_id: null, ip: null, expires_at: null, dry_run: null,
          refused: "protected host", error: null, command_id: null,
        },
      }),
    ).toBe("failed: protected host");
    expect(
      summarize({
        seq: 2, type: "DEVICE_RESTORED", ts: "", node_id: "dev-a",
        payload: { quarantine_id: 1, ip: "10.77.1.74" },
      }),
    ).toBe("released 10.77.1.74");
  });
});
