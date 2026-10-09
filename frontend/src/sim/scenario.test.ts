import { describe, expect, it } from "vitest";
import { api, setHostedMode } from "../api/client";
import { graphFromPaths } from "../visuals/model";
import { COMMS, formatCoordinate, isSimulatedIoc, REPORT, SIM_IOC, simulatedCounts, simulatedThreats } from "./scenario";

describe("simulated investigation", () => {
  it("matches only the scenario indicator", () => {
    expect(isSimulatedIoc(" 138.987.22.22 ")).toBe(true);
    expect(isSimulatedIoc("138.98.22.22")).toBe(false);
  });

  it("every path starts at the indicator and the graph links malware, crypto and the consignment", () => {
    const threats = simulatedThreats();
    for (const t of threats) {
      expect(t.path[0]?.name).toBe(SIM_IOC);
      expect(t.hops).toBe(t.path.length - 1);
    }
    const graph = graphFromPaths(threats.map((t) => t.path));
    const kinds = graph.nodes.map((n) => n.kind);
    expect(kinds.filter((k) => k === "Malware").length).toBeGreaterThanOrEqual(4);
    expect(kinds.filter((k) => k === "Ledger").length).toBeGreaterThanOrEqual(3);
    expect(kinds).toContain("Consignment");
    expect(graph.edges.length).toBe(simulatedCounts().relationships);
    // The consignment is reachable from the indicator through the crypto trail.
    const toConsignment = threats.find((t) => t.label === "Consignment");
    expect(toConsignment?.path.map((s) => s.label)).toContain("Ledger");
  });

  it("three devices talk to the indicator: one in Russia, two in Sri Lanka", () => {
    expect(COMMS.map((d) => d.country)).toEqual(["Russia", "Sri Lanka", "Sri Lanka"]);
    // RFC 5737 documentation ranges only.
    for (const d of COMMS) expect(d.ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
  });

  it("uses only synthetic identifiers", () => {
    for (const t of REPORT.transfers) {
      if (t.from.startsWith("bc1") || t.to.startsWith("bc1")) expect(`${t.from} ${t.to}`).toMatch(/bc1qsim/);
    }
    expect(formatCoordinate(REPORT.consignment.lat, REPORT.consignment.lon)).toBe("18.5204° N, 66.0412° E");
  });

  it("the API client answers the scenario indicator locally", async () => {
    setHostedMode(true);
    expect(await api.relatedThreats(SIM_IOC)).toHaveLength(simulatedThreats().length);
    expect((await api.graphCounts()).Consignment).toBe(1);
    setHostedMode(false);
  });
});
