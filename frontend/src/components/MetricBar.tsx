export function MetricBar({ value, max = 100, tone = "signal" }: { value: number | null | undefined; max?: number; tone?: string }) {
  if (value == null || !Number.isFinite(value)) return <span className="text-ink-400">n/a</span>;
  return <span className="metric-bar" role="meter" aria-label="Measured value" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max}><span style={{ width: `${Math.max(0, Math.min(100, value / max * 100))}%`, background: `var(--color-${tone})` }} /></span>;
}
