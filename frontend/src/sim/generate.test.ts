import { describe, expect, it } from "vitest";
import { graphFromPaths } from "../visuals/model";
import { generateScenario, isIpLike, scenarioFor } from "./generate";
import { HANDCRAFTED, SIM_IOC } from "./scenario";

const DAY = new Date("2026-10-09T12:00:00Z");

describe("generated scenarios", () => {
  it("are deterministic per address and differ between addresses", () => {
    const a = generateScenario("45.33.32.156", DAY);
    expect(generateScenario("45.33.32.156", DAY)).toEqual(a);
    const b = generateScenario("45.33.32.157", DAY);
    expect(b.report.subdomains.map((s) => s.host)).not.toEqual(a.report.subdomains.map((s) => s.host));
  });

  it("show 3 devices in different countries on documentation-range addresses", () => {
    for (const ip of ["8.8.8.8", "1.2.3.4", "203.0.113.9", "10.0.0.1"]) {
      const s = generateScenario(ip, DAY);
      expect(s.comms).toHaveLength(3);
      expect(new Set(s.comms.map((d) => d.country)).size).toBe(3);
      for (const d of s.comms) expect(d.ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/);
      const [[x0, y0], [x1, y1]] = s.map.extent;
      for (const d of s.comms) {
        expect(d.lon).toBeGreaterThanOrEqual(x0);
        expect(d.lon).toBeLessThanOrEqual(x1);
        expect(d.lat).toBeGreaterThanOrEqual(y0);
        expect(d.lat).toBeLessThanOrEqual(y1);
      }
    }
  });

  it("mark each subdomain malicious with an associated malware family", () => {
    const s = generateScenario("8.8.8.8", DAY);
    expect(s.report.subdomains.length).toBeGreaterThanOrEqual(3);
    const families = new Set(s.report.malware.map((m) => m.family));
    for (const sub of s.report.subdomains) {
      expect(sub.host).toMatch(/^[a-z]+\.[a-z][a-z0-9]{9,11}\.[a-z]+$/);
      expect(families.has(sub.malware)).toBe(true);
    }
    // Graph: indicator -> subdomain -> malware, unique row ids.
    const graph = graphFromPaths(s.threats.map((t) => t.path));
    expect(graph.nodes.filter((n) => n.kind === "Malware").length).toBe(families.size);
    expect(new Set(s.threats.map((t) => t.threat_id)).size).toBe(s.threats.length);
  });

  it("apply to any IPv4 when hosted, and only the hand-built indicator in the lab", () => {
    expect(scenarioFor(SIM_IOC, false)).toBe(HANDCRAFTED);
    expect(scenarioFor("8.8.8.8", false)).toBeNull();
    expect(scenarioFor("8.8.8.8", true)?.comms).toHaveLength(3);
    expect(scenarioFor("8.8.8.8", true)).toBe(scenarioFor(" 8.8.8.8 ", true));
    expect(scenarioFor("example.com", true)).toBeNull();
    expect(isIpLike("138.987.22.22")).toBe(true);
  });
});
