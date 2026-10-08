import type { RiskLevel } from "../api/types";

// Mirrors the @theme tokens in styles.css (the WebGL scene can't read CSS vars cheaply).
export const LEVEL_COLOR: Record<RiskLevel, string> = {
  low: "#19D89A",
  medium: "#FFC928",
  high: "#FF9F2D",
  critical: "#FF315A",
};
export const QUARANTINE_COLOR = "#FF315A";
export const UNSCORED_COLOR = "#78909F";
export const SIGNAL_COLOR = "#00D9FF";

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
