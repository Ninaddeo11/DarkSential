import type { RiskDecision, RiskLevel } from "../api/types";
import { LEVEL_COLOR } from "../viz/colors";

const W = 640;
const H = 170;
const PAD = { l: 34, r: 92, t: 10, b: 22 };

/** Score over time for one device, with the level thresholds as reference lines. */
export function RiskHistory({
  history,
  thresholds,
}: {
  history: RiskDecision[];
  thresholds: Partial<Record<RiskLevel, number>> | null;
}) {
  const points = [...history].sort((a, b) => a.ts.localeCompare(b.ts));
  if (points.length < 2) {
    return <p className="px-3 pb-3 text-xs text-ink-400">Not enough assessments for a history yet.</p>;
  }
  const t0 = new Date(points[0]!.ts).getTime();
  const t1 = new Date(points.at(-1)!.ts).getTime();
  const span = Math.max(1, t1 - t0);
  const maxScore = Math.max(40, ...points.map((p) => p.score)) * 1.1;
  const x = (ts: string) => PAD.l + ((new Date(ts).getTime() - t0) / span) * (W - PAD.l - PAD.r);
  const y = (s: number) => H - PAD.b - (s / maxScore) * (H - PAD.t - PAD.b);
  const path = points.map((p, i) => `${i ? "L" : "M"}${x(p.ts).toFixed(1)},${y(p.score).toFixed(1)}`).join(" ");
  const fmt = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Risk score history">
      {(["medium", "high", "critical"] as const).map((lvl) => {
        const v = thresholds?.[lvl];
        if (v === undefined) return null;
        return (
          <g key={lvl}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(v)} y2={y(v)} stroke={LEVEL_COLOR[lvl]} strokeOpacity={0.45} strokeDasharray="4 4" />
            <text x={W - PAD.r + 6} y={y(v) + 3} fontSize={10} fill="#93a4bb">
              {lvl} {v}
            </text>
          </g>
        );
      })}
      <line x1={PAD.l} x2={W - PAD.r} y1={H - PAD.b} y2={H - PAD.b} stroke="#2b3a4f" />
      <text x={PAD.l - 6} y={y(0) + 3} textAnchor="end" fontSize={10} fill="#6b7f99">0</text>
      <text x={PAD.l - 6} y={y(Math.round(maxScore / 1.1)) + 3} textAnchor="end" fontSize={10} fill="#6b7f99">
        {Math.round(maxScore / 1.1)}
      </text>
      <text x={PAD.l} y={H - 6} fontSize={10} fill="#6b7f99">{fmt(t0)}</text>
      <text x={W - PAD.r} y={H - 6} textAnchor="end" fontSize={10} fill="#6b7f99">{fmt(t1)}</text>
      <path d={path} fill="none" stroke="#38d6f5" strokeWidth={2} strokeLinejoin="round" />
      {points.map((p) => (
        <circle key={p.id} cx={x(p.ts)} cy={y(p.score)} r={4} fill={LEVEL_COLOR[p.level]} stroke="#0e1520" strokeWidth={2}>
          <title>{`${new Date(p.ts).toLocaleTimeString()} · ${p.score} (${p.level}, ${p.action}) · trigger ${p.trigger}`}</title>
        </circle>
      ))}
    </svg>
  );
}
