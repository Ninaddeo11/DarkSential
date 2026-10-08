import type { RiskLevel } from "../api/types";

// Mirrors the @theme tokens in styles.css (the WebGL scene can't read CSS vars cheaply).
export const LEVEL_COLOR: Record<RiskLevel, string> = {
  low: "#34d399",
  medium: "#fbbf24",
  high: "#fb923c",
  critical: "#f43f5e",
};
export const QUARANTINE_COLOR = "#e879f9";
export const UNSCORED_COLOR = "#6b7f99";
export const SIGNAL_COLOR = "#38d6f5";

export function nodeColor(level: RiskLevel | null, quarantined: boolean): string {
  if (quarantined) return QUARANTINE_COLOR;
  return level ? LEVEL_COLOR[level] : UNSCORED_COLOR;
}

export const LEVEL_TEXT: Record<RiskLevel, string> = {
  low: "text-low",
  medium: "text-medium",
  high: "text-high",
  critical: "text-critical",
};
