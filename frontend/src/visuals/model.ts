import type { PathStep } from "../api/types";

export type SceneMode = "network" | "globe" | "specimen" | "pipeline" | "scanner" | "ecosystem" | "terrain" | "routes" | "evidence";
export interface IntelligenceNode {
  id: string;
  label: string;
  kind: string;
  detail?: string;
  color?: string;
  value?: number;
}
export interface IntelligenceEdge { source: string; target: string; label?: string }
export interface IntelligenceGraph { nodes: IntelligenceNode[]; edges: IntelligenceEdge[] }

export const ENTITY_COLOR: Record<string, string> = {
  Device: "#00D9FF", Infrastructure: "#168BFF", Indicator: "#FFC928",
  Observable: "#00D9FF", Vulnerability: "#FF9F2D", CPE: "#8EA3B2",
  Malware: "#A855F7", IntrusionSet: "#A855F7", ThreatActor: "#A855F7",
  Identity: "#168BFF", Report: "#8EA3B2", AttackPattern: "#A855F7",
};

/** Preserve the backend's entity IDs and relationships; limit only the visual projection. */
export function graphFromPaths(paths: PathStep[][], limit = 36): IntelligenceGraph {
  const nodes = new Map<string, IntelligenceNode>();
  const edges = new Map<string, IntelligenceEdge>();
  for (const path of paths) {
    for (let i = 0; i < path.length; i++) {
      const step = path[i]!;
      if (!nodes.has(step.node_id) && nodes.size < limit) nodes.set(step.node_id, {
        id: step.node_id, label: step.name ?? step.node_id, kind: step.label,
        detail: step.node_id, color: ENTITY_COLOR[step.label] ?? "#8EA3B2",
      });
      const previous = path[i - 1];
      if (previous && nodes.has(previous.node_id) && nodes.has(step.node_id)) {
        const key = `${previous.node_id}>${step.node_id}:${step.via ?? ""}`;
        edges.set(key, { source: previous.node_id, target: step.node_id, label: step.via ?? undefined });
      }
    }
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

export const TAXONOMY = [
  { id: "weapons", label: "Weapons", kind: "Evidence", detail: "Research signals associated with illicit weapons activity. An evidence category, never a procurement channel." },
  { id: "narcotics", label: "Narcotics", kind: "Evidence", detail: "Study patterns associated with illicit narcotics ecosystems through source provenance and corroborated evidence." },
  { id: "malware", label: "Malware", kind: "Malware", detail: "Connect malware names, indicators, infrastructure and ATT&CK techniques in the intelligence graph." },
  { id: "identities", label: "Stolen identities", kind: "Identity", detail: "Examine identity-related intelligence objects. An identity object is not evidence of a compromised person." },
  { id: "crypto", label: "Crypto activity", kind: "Ledger", detail: "A research lens for transaction relationships and financial infrastructure. Wallet coverage is not measured in this deployment." },
  { id: "trafficking", label: "Trafficking networks", kind: "Network", detail: "Analyze documented associations and infrastructure as a forensic research category, without operational routes or acquisition information." },
  { id: "exploits", label: "Exploits", kind: "Vulnerability", detail: "Correlate product identifiers with CVEs, CVSS severity and CISA KEV evidence from configured sources." },
  { id: "infrastructure", label: "Underground infrastructure", kind: "Infrastructure", detail: "Investigate abstract service, hosting and communication relationships through corroborated source evidence." },
] satisfies IntelligenceNode[];

export const PIPELINE: IntelligenceNode[] = ["Collect", "Correlate", "Analyze", "Score", "Respond"].map((label,i) => ({ id: `stage-${i}`, label, kind: "Stage", detail: "Conceptual intelligence workflow", color: i === 3 ? "#FF9F2D" : "#00D9FF" }));
export function sequentialEdges(nodes: IntelligenceNode[]): IntelligenceEdge[] {
  return nodes.slice(1).map((n,i) => ({ source: nodes[i]!.id, target: n.id, label: "NEXT STAGE" }));
}
