import type { Contribution } from "../generated/events";

export interface WaterfallBar {
  factor: string;
  start: number; // cumulative score before this factor
  end: number; // cumulative score after it
  contribution: number;
  value: number;
  weight: number;
}

/** Risk score as a waterfall: 0 -> each factor's contribution -> total.
 * Largest contributors first; zero contributions are kept (they explain why a
 * factor did *not* count). The last bar ends exactly at the score. */
export function waterfall(contributions: Contribution[]): WaterfallBar[] {
  const sorted = [...contributions].sort(
    (a, b) => b.contribution - a.contribution || a.factor.localeCompare(b.factor),
  );
  let acc = 0;
  return sorted.map((c) => {
    const bar = {
      factor: c.factor,
      start: acc,
      end: acc + c.contribution,
      contribution: c.contribution,
      value: c.value,
      weight: c.weight,
    };
    acc += c.contribution;
    return bar;
  });
}

/** SHAP values sorted by absolute impact, for a diverging bar chart. */
export function shapBars(shap: Record<string, number>): Array<{ feature: string; value: number }> {
  return Object.entries(shap)
    .map(([feature, value]) => ({ feature, value }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value) || a.feature.localeCompare(b.feature));
}

export const FACTOR_LABELS: Record<string, string> = {
  unknown_device: "Unknown device",
  rate_anomaly: "Rate anomaly",
  protocol_anomaly: "Protocol anomaly",
  threat_intel: "Threat intel",
  vulnerable_service: "Vulnerable service",
};
