import type { Contribution } from "../generated/events";
import type { MlExplanation } from "../api/types";
import { FACTOR_LABELS, shapBars, waterfall } from "../viz/waterfall";

const W = 300;
const ROW = 22;
const LABEL = 118;

/** Score as a waterfall: each factor's weighted contribution, adding up to the score. */
export function RiskWaterfall({ contributions, score }: { contributions: Contribution[]; score: number }) {
  const bars = waterfall(contributions);
  const scale = (W - LABEL - 34) / 100;
  const height = (bars.length + 1) * ROW + 6;
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${height}`} role="img" aria-label="Risk score waterfall">
      {[0, 25, 50, 75, 100].map((tick) => (
        <line
          key={tick}
          x1={LABEL + tick * scale}
          x2={LABEL + tick * scale}
          y1={0}
          y2={height - 4}
          stroke="#1d2939"
          strokeDasharray="2 3"
        />
      ))}
      {bars.map((b, i) => (
        <g key={b.factor} transform={`translate(0 ${i * ROW + 4})`}>
          <title>
            {`${FACTOR_LABELS[b.factor] ?? b.factor}: value ${b.value.toFixed(2)} × weight ${b.weight} = +${b.contribution.toFixed(1)}`}
          </title>
          <text x={LABEL - 6} y={13} textAnchor="end" fontSize={10} fill="#93a4bb">
            {FACTOR_LABELS[b.factor] ?? b.factor}
          </text>
          <rect
            x={LABEL + b.start * scale}
            y={3}
            width={Math.max(b.contribution * scale, b.contribution > 0 ? 1.5 : 0)}
            height={ROW - 8}
            rx={2}
            fill={b.contribution > 0 ? "#38d6f5" : "#2b3a4f"}
            opacity={0.85}
          />
          <text x={LABEL + b.end * scale + 4} y={13} fontSize={10} fill="#dce6f2" fontFamily="monospace">
            {b.contribution > 0 ? `+${b.contribution.toFixed(1)}` : "0"}
          </text>
        </g>
      ))}
      <g transform={`translate(0 ${bars.length * ROW + 4})`}>
        <text x={LABEL - 6} y={13} textAnchor="end" fontSize={10} fontWeight={600} fill="#dce6f2">
          Score
        </text>
        <rect x={LABEL} y={3} width={score * scale} height={ROW - 8} rx={2} fill="#dce6f2" opacity={0.9} />
        <text x={LABEL + score * scale + 4} y={13} fontSize={10} fontWeight={600} fill="#dce6f2" fontFamily="monospace">
          {score.toFixed(1)}
        </text>
      </g>
    </svg>
  );
}

/** XGBoost comparison opinion: SHAP values (log-odds) per feature, diverging from 0. */
export function ShapChart({ ml }: { ml: MlExplanation }) {
  const bars = shapBars(ml.shap).slice(0, 8);
  const max = Math.max(0.01, ...bars.map((b) => Math.abs(b.value)));
  const mid = LABEL + (W - LABEL) / 2;
  const half = (W - LABEL) / 2 - 30;
  const height = bars.length * ROW + 6;
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${height}`} role="img" aria-label="SHAP feature contributions">
      <line x1={mid} x2={mid} y1={0} y2={height} stroke="#2b3a4f" />
      {bars.map((b, i) => {
        const len = (Math.abs(b.value) / max) * half;
        const up = b.value >= 0;
        return (
          <g key={b.feature} transform={`translate(0 ${i * ROW + 3})`}>
            <title>{`${b.feature} = ${ml.features[b.feature] ?? "?"}: SHAP ${b.value.toFixed(3)}`}</title>
            <text x={LABEL - 6} y={13} textAnchor="end" fontSize={10} fill="#93a4bb">
              {b.feature}
            </text>
            <rect
              x={up ? mid : mid - len}
              y={3}
              width={Math.max(len, 1)}
              height={ROW - 8}
              rx={2}
              fill={up ? "#f43f5e" : "#34d399"}
              opacity={0.8}
            />
            <text
              x={up ? mid + len + 4 : mid - len - 4}
              y={13}
              textAnchor={up ? "start" : "end"}
              fontSize={9}
              fill="#93a4bb"
              fontFamily="monospace"
            >
              {b.value >= 0 ? "+" : ""}
              {b.value.toFixed(2)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
