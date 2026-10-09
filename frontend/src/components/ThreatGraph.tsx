import type { PathStep } from "../api/types";

const COL_W = 136; // room for the relationship label between columns
const ROW_H = 46;
const NODE_W = 92;
const NODE_H = 30;

const LABEL_COLOR: Record<string, string> = {
  Device: "#00D9FF",
  CPE: "#8EA3B2",
  Vulnerability: "#FF9F2D",
  Indicator: "#FFC928",
  Observable: "#FFC928",
  Malware: "#FF315A",
  IntrusionSet: "#FF315A",
  ThreatActor: "#FF315A",
  Campaign: "#FF315A",
  Report: "#a78bfa",
  AttackPattern: "#60a5fa",
  Infrastructure: "#168BFF",
  Ledger: "#22C55E",
  Consignment: "#F43F5E",
};

interface Placed {
  step: PathStep;
  col: number;
  row: number;
}

/** Evidence paths from the threat graph (device -> CPE -> CVE, IOC -> malware...),
 * merged into one layered diagram: column = hop, shared nodes drawn once. */
export function ThreatGraph({ paths }: { paths: PathStep[][] }) {
  if (!paths.length) {
    return <p className="px-3 pb-3 text-xs text-ink-400">No threat-graph links for this device.</p>;
  }
  const placed = new Map<string, Placed>();
  const perCol: number[] = [];
  const links = new Map<string, { from: string; to: string; via: string | null }>();
  for (const path of paths.slice(0, 12)) {
    path.forEach((step, col) => {
      if (!placed.has(step.node_id)) {
        const row = perCol[col] ?? 0;
        perCol[col] = row + 1;
        placed.set(step.node_id, { step, col, row });
      }
      const prev = col > 0 ? path[col - 1] : undefined;
      if (prev) {
        const from = prev.node_id;
        links.set(`${from}>${step.node_id}`, { from, to: step.node_id, via: step.via });
      }
    });
  }
  const cols = perCol.length;
  const rows = Math.max(...perCol);
  const width = cols * COL_W;
  const height = rows * ROW_H;
  const center = (p: Placed): [number, number] => [p.col * COL_W + NODE_W / 2, p.row * ROW_H + NODE_H / 2 + 4];
  return (
    <div className="scroll-thin overflow-x-auto px-3 pb-3">
      <svg width={width} height={height + 8} role="img" aria-label="Threat evidence graph">
        {[...links.values()].map((l) => {
          const a = placed.get(l.from);
          const b = placed.get(l.to);
          if (!a || !b) return null;
          const [x1, y1] = center(a);
          const [x2, y2] = center(b);
          const sx = x1 + NODE_W / 2;
          const ex = x2 - NODE_W / 2;
          return (
            <g key={`${l.from}>${l.to}`}>
              <path
                d={`M${sx},${y1} C${sx + 10},${y1} ${ex - 10},${y2} ${ex},${y2}`}
                fill="none"
                stroke="#223443"
                strokeWidth={1.5}
              />
              {l.via && (
                <text x={(sx + ex) / 2} y={(y1 + y2) / 2 - 3} textAnchor="middle" fontSize={7} fill="#78909F">
                  {l.via.toLowerCase().replace(/_/g, " ")}
                </text>
              )}
            </g>
          );
        })}
        {[...placed.values()].map((p) => {
          const [cx, cy] = center(p);
          const color = LABEL_COLOR[p.step.label] ?? "#8EA3B2";
          const name = p.step.name ?? p.step.node_id;
          const short = name.startsWith("cpe:2.3:") ? name.split(":").slice(3, 6).join(":") : name;
          return (
            <g key={p.step.node_id}>
              <title>{`${p.step.label}: ${name}`}</title>
              <rect
                x={cx - NODE_W / 2}
                y={cy - NODE_H / 2}
                width={NODE_W}
                height={NODE_H}
                rx={5}
                fill="#0B1118"
                stroke={color}
                strokeWidth={1}
              />
              <text x={cx} y={cy - 3} textAnchor="middle" fontSize={7} fill={color} letterSpacing={0.6}>
                {p.step.label.toUpperCase()}
              </text>
              <text x={cx} y={cy + 8} textAnchor="middle" fontSize={8.5} fill="#E8F2F7">
                {short.length > 17 ? `${short.slice(0, 16)}…` : short}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
