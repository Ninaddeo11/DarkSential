import type { CSSProperties } from "react";
import type { DsnEvent } from "../generated/events";
import type { NodeState } from "../live/store";
import { LEVEL_COLOR } from "../viz/colors";
import { motion, useReducedMotion } from 'framer-motion';

export function ThreatGauge({ score, level }: { score: number | null; level: NodeState["level"] }) {
  const reduced=useReducedMotion();
  const color = level ? LEVEL_COLOR[level] : "#78909f";
  const fraction = Math.max(0, Math.min(100, score ?? 0)) / 100;
  return <div className="threat-gauge" style={{ "--threat-tone": color } as CSSProperties}>
    <svg viewBox="0 0 240 145" role="img" aria-label={`Risk score ${score?.toFixed(1) ?? "unscored"} of 100, ${level ?? "unscored"}`}>
      <path d="M28 116A92 92 0 0 1 212 116" fill="none" stroke="#223443" strokeWidth="7" pathLength="100" />
      <motion.path d="M28 116A92 92 0 0 1 212 116" fill="none" stroke={color} strokeWidth="7" pathLength="100" initial={false} animate={{strokeDasharray:`${fraction * 100} 100`}} transition={{duration:reduced?0:.4}} />
      <path d="M42 116A78 78 0 0 1 198 116" fill="none" stroke="#223443" strokeWidth="1" strokeDasharray="1 8" />
      <text x="120" y="97" textAnchor="middle" fill="#e8f2f7" fontSize="46" fontFamily="var(--font-mono)" fontWeight="600">{score?.toFixed(1) ?? "--"}</text>
      <text x="120" y="120" textAnchor="middle" fill="#8ea3b2" fontSize="9" letterSpacing="2">RISK SCORE / 100</text>
      <text x="22" y="140" fill="#78909f" fontSize="9">0</text><text x="201" y="140" fill="#78909f" fontSize="9">100</text>
    </svg>
  </div>;
}

/** Timestamped counts from the retained event buffer, never a simulated series. */
export function ThreatActivity({ events, rate }: { events: DsnEvent[]; rate: number }) {
  const times = events.map(e => new Date(e.ts).getTime()).filter(Number.isFinite);
  const start = times.length ? Math.min(...times) : 0;
  const end = times.length ? Math.max(...times) : 0;
  const bucketMs = Math.max(1000, Math.ceil((end - start + 1) / 20));
  const bins = Array.from({ length: times.length ? Math.floor((end - start) / bucketMs) + 1 : 0 }, () => ({ total: 0, threat: 0, anomaly: 0 }));
  for (const e of events) {
    const i = Math.floor((new Date(e.ts).getTime() - start) / bucketMs);
    const bin = bins[i];
    if (!bin) continue;
    bin.total++;
    if (e.type === "THREAT_CORRELATED") bin.threat++;
    if (e.type === "ANOMALY_DETECTED") bin.anomaly++;
  }
  const max = Math.max(1, ...bins.map(b => b.total));
  const points: [number, number][] = bins.map((b,i) => [bins.length === 1 ? 220 : 24 + i / (bins.length - 1) * 392, 100 - b.total / max * 70]);
  const time = (t: number) => new Date(t).toLocaleTimeString([], { hour12: false });
  return <section className="panel telemetry-activity">
    <div className="command-section-title"><div><span className="section-eyebrow">01 / SIGNAL HISTORY</span><h2>Threat activity</h2></div><span className="technical-badge">EVENT BUFFER</span></div>
    <dl className="activity-values"><div><dt>Event rate</dt><dd>{rate.toFixed(1)}<small>/s</small></dd></div><div><dt>Threat signals</dt><dd>{events.filter(e => e.type === "THREAT_CORRELATED").length}</dd></div><div><dt>Anomalies</dt><dd>{events.filter(e => e.type === "ANOMALY_DETECTED").length}</dd></div></dl>
    {bins.length ? <svg viewBox="0 0 440 125" className="activity-chart" role="img" aria-label={`Buffered event counts from ${time(start)} to ${time(end)}. Peak ${max} events per bucket.`}>
      {[30,65,100].map(y => <path key={y} d={`M24 ${y}H416`} stroke="#182532" strokeWidth="1" />)}
      <text x="4" y="32" fill="#78909f" fontSize="8">{max}</text><text x="8" y="103" fill="#78909f" fontSize="8">0</text>
      {points.length > 1 && <><path d={`M${points[0]![0]} 100L${points.map(p=>p.join(" ")).join("L")}L${points.at(-1)![0]} 100Z`} fill="#00d9ff09" /><polyline points={points.map(p=>p.join(",")).join(" ")} fill="none" stroke="#00d9ff" strokeWidth="1.5" /></>}
      {points.map(([x,y],i) => <g key={i}><path d={`M${x} 100V${y}`} stroke={bins[i]!.threat ? "#ff315a" : "#00d9ff"} strokeWidth={points.length === 1 ? 3 : 1} opacity=".5" /><circle cx={x} cy={y} r="3" fill={bins[i]!.threat ? "#ff315a" : "#00d9ff"}><title>{bins[i]!.total} events / {bins[i]!.threat} threats / {bins[i]!.anomaly} anomalies</title></circle></g>)}
      <text x="24" y="120" fill="#8ea3b2" fontSize="9">{time(start)}</text><text x="416" y="120" textAnchor="end" fill="#8ea3b2" fontSize="9">{time(end)}</text>
    </svg> : <p className="telemetry-empty">No timestamped events in the buffer.</p>}
  </section>;
}

export function AssetPosture({ nodes }: { nodes: NodeState[] }) {
  const rows = [
    { label: "Monitored", value: nodes.length, tone: "signal" },
    { label: "Critical risk", value: nodes.filter(n=>n.level === "critical").length, tone: "critical" },
    { label: "Unknown trust", value: nodes.filter(n=>n.device.trust === "unknown").length, tone: "ink-300" },
    { label: "Quarantined", value: nodes.filter(n=>n.quarantined).length, tone: "critical" },
  ];
  return <section className="panel asset-posture"><div className="command-section-title"><div><span className="section-eyebrow">02 / ASSET POSTURE</span><h2>Device health</h2></div><strong>{String(nodes.length).padStart(2,"0")}</strong></div>
    <div className="asset-health-rows">{rows.map(r => <div key={r.label}><span>{r.label}</span><strong>{String(r.value).padStart(2,"0")}</strong><span className="segmented-meter" aria-label={`${r.label}: ${r.value} of ${nodes.length}`} style={{ "--meter-color": `var(--color-${r.tone})` } as CSSProperties}><span style={{width:`${nodes.length ? r.value/nodes.length*100 : 0}%`}} /></span></div>)}</div>
  </section>;
}
