import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type FormEvent } from "react";
import { Link } from "react-router";
import { Inspector } from "../components/Inspector";
import { Legend } from "../components/Legend";
import { summarize } from "../components/Timeline";
import { AssetPosture, ThreatActivity, ThreatGauge } from "../components/CommandTelemetry";
import { useLive } from "../live/LiveContext";
import { LEVEL_COLOR, LEVEL_TEXT } from "../viz/colors";
import { isHostedMode } from "../api/client";
import { isIpLike, scenarioFor } from "../sim/generate";
import { SIM_IOC, type Scenario } from "../sim/scenario";

const Graph3D = lazy(() => import("../components/Graph3D").then((m) => ({ default: m.Graph3D })));
const CommsTraceMap = lazy(() => import("../components/CommsTraceMap").then((m) => ({ default: m.CommsTraceMap })));
const CommsDeviceTable = lazy(() => import("../components/CommsTraceMap").then((m) => ({ default: m.CommsDeviceTable })));
const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export function OverviewPage() {
  const { state, role, health, rate, link } = useLive();
  const [graphVersion, setGraphVersion] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const inspectButton = useRef<HTMLButtonElement>(null);
  // Indicator trace: devices in active communication with an indicator.
  const [traceInput, setTraceInput] = useState("");
  const [trace, setTrace] = useState<Scenario | null>(null);
  const [traceMsg, setTraceMsg] = useState<string | null>(null);
  const [traceSel, setTraceSel] = useState<string | null>(null);
  useEffect(() => { if (health?.deployment === "hosted") setTraceInput((v) => v || SIM_IOC); }, [health?.deployment]);
  const runTrace = (e: FormEvent) => {
    e.preventDefault();
    const value = traceInput.trim();
    setTraceSel(null);
    const found = scenarioFor(value, isHostedMode());
    if (found) { setTrace(found); setTraceMsg(null); }
    else { setTrace(null); setTraceMsg(isIpLike(value) ? `No devices in active communication with ${value}.` : "Enter an IPv4 address to trace."); }
  };
  useEffect(() => {
    if (!selected) return;
    const timer = window.setTimeout(() => document.querySelector<HTMLButtonElement>('[aria-label="Close inspector"]')?.focus(), 0);
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setSelected(null); inspectButton.current?.focus(); } };
    window.addEventListener("keydown", onKey);
    return () => { window.clearTimeout(timer); window.removeEventListener("keydown", onKey); };
  }, [selected]);
  const onSelect = useCallback((id: string | null) => setSelected(id), []);
  const nodes = Object.values(state.nodes);
  const priority = [...nodes].sort((a,b) => (b.level ? RANK[b.level] : 0) - (a.level ? RANK[a.level] : 0) || (b.score ?? -1) - (a.score ?? -1))[0];
  const elevated = nodes.filter(n => n.level === "critical" || n.level === "high" || n.level === "medium");
  const tone = priority?.level ? LEVEL_COLOR[priority.level] : "#78909f";
  const evidence = useMemo(() => {
    const out: Record<string,string> = {};
    for (const e of state.events) if (e.node_id && e.type === "THREAT_CORRELATED") out[e.node_id] = e.payload.summary;
    return out;
  },[state.events]);
  const priorityEvidence = priority ? evidence[priority.device.node_id] : undefined;
  const cve = priorityEvidence?.match(/CVE-\d{4}-\d+/i)?.[0];
  const selectedNode = selected ? state.nodes[selected] : undefined;
  const lastEvent = state.events.at(-1);
  const incidentEvents = state.events.filter(e=>["THREAT_CORRELATED","ANOMALY_DETECTED","QUARANTINE_COMPLETED"].includes(e.type)).slice(-2).reverse();
  const latest = [...incidentEvents, ...state.events.slice(-5).reverse().filter(e=>!incidentEvents.some(i=>i.seq === e.seq))].slice(0,4);
  const posture = !nodes.length ? "Awaiting assets" : priority?.level === "critical" ? "Critical" : elevated.length ? "Elevated risk" : nodes.some(n=>!n.level) ? "Assessment pending" : "Low risk";
  return <div className="command-overview" style={{ "--threat-tone": tone } as CSSProperties}>
    <header className="overview-heading">
      <div><p className="section-eyebrow">LIVE THREAT INTELLIGENCE OPERATIONS</p><h1>Network command center<span className="heading-period">.</span></h1></div>
      <div className="overview-status"><span className={`status-light ${link === "live" ? "live-dot" : ""}`} data-state={link} /><div><strong>{link === "live" ? "Live telemetry" : link === "simulated" ? "Simulated feed" : link === "connecting" ? "Connecting" : link === "unauthorized" ? "Authentication required" : "Reconnecting"}</strong><span>{lastEvent ? `LAST EVENT / ${new Date(lastEvent.ts).toLocaleTimeString([], { hour12: false })}` : "AWAITING EVENT DATA"}</span></div></div>
    </header>
    <form className="workspace-query panel" onSubmit={runTrace} aria-label="Trace an indicator">
      <label htmlFor="trace-indicator">TRACE INDICATOR / ACTIVE COMMUNICATIONS</label>
      <div><span className="terminal-prompt" aria-hidden="true">&#10095;</span><input id="trace-indicator" className="input" value={traceInput} onChange={(e) => setTraceInput(e.target.value)} placeholder="IP address to trace" maxLength={200} /><button className="btn command-action" disabled={!traceInput.trim()}>Trace</button>{trace && <button type="button" className="btn" onClick={() => { setTrace(null); setTraceSel(null); }}>Back to topology</button>}</div>
      {traceMsg && <p className="mt-1 text-xs text-ink-400">{traceMsg}</p>}
    </form>
    <div className="command-hero">
      {trace ? <section className="hero-network panel">
        <div className="command-section-title"><div><span className="section-eyebrow">INDICATOR TRACE / ACTIVE COMMUNICATIONS</span><h2>{trace.ioc}: {trace.comms.length} devices in active communication</h2></div><Link className="btn" to="/threat-intel">Open dossier &#8599;</Link></div>
        <div className="network-meta"><span className="text-critical"><strong>{String(trace.comms.length).padStart(2,"0")}</strong> ACTIVE DEVICES</span><span><strong>{String(new Set(trace.comms.map(d=>d.country)).size).padStart(2,"0")}</strong> COUNTRIES</span><span>{trace.comms.map(d=>`${d.name.toUpperCase()}: ${d.country.toUpperCase()}`).join(" / ")}</span></div>
        <div className="min-h-0 flex-1 px-3 pb-3"><Suspense fallback={<div className="map-loading">Loading trace map...</div>}><CommsTraceMap key={trace.ioc} scenario={trace} selected={traceSel} onSelect={(id)=>setTraceSel(s=>s===id?null:id)} /></Suspense></div>
      </section> : <section className="hero-network panel">
        <div className="command-section-title"><div><span className="section-eyebrow">NETWORK / TOPOLOGY</span><h2>Network threat map</h2></div><button className="btn" onClick={() => setGraphVersion(v=>v+1)}>Reset view</button></div>
        <div className="network-meta"><span><strong>{String(nodes.length).padStart(2,"0")}</strong> ASSETS</span><span className={priority?.level ? LEVEL_TEXT[priority.level] : ""}><strong>{String(elevated.length).padStart(2,"0")}</strong> ELEVATED RISK</span><span className="network-meta-time">{lastEvent ? `LAST EVENT ${new Date(lastEvent.ts).toLocaleTimeString([],{hour12:false})}` : "NO EVENT DATA"}</span></div>
        <div className="hero-graph"><Suspense fallback={<div className="map-loading">Loading network topology...</div>}><Graph3D key={graphVersion} nodes={state.nodes} selected={selected} onSelect={onSelect} evidence={evidence} live={link === "live"} /></Suspense>
          {!nodes.length && <p className="map-empty">No devices are currently available.</p>}
        </div>
        <div className="map-footer"><span><i className="legend-dot" style={{background:"#00d9ff"}} />GATEWAY</span><span><i className="legend-dot" style={{background:"#19d89a"}} />LOW RISK</span><span><i className="legend-dot" style={{background:"#ff315a"}} />CRITICAL</span><span>SELECT AN ASSET TO INSPECT</span></div>
      </section>}
      <aside className="threat-command panel">
        <div className="threat-heading"><span className="section-eyebrow">SECURITY POSTURE</span><span className="posture-label">{trace ? "Critical" : posture}</span><p>{trace ? `${String(trace.comms.length).padStart(2,"0")} DEVICES IN ACTIVE COMMUNICATION` : elevated.length ? `${String(elevated.length).padStart(2,"0")} ${elevated.length === 1 ? "ASSET REQUIRES" : "ASSETS REQUIRE"} REVIEW` : `${String(nodes.length).padStart(2,"0")} ASSETS IN INVENTORY`}</p></div>
        <ThreatGauge score={trace ? trace.report.score : priority?.score ?? null} level={trace ? "critical" : priority?.level ?? null} />
        {trace ? <div className="priority-evidence"><span className="section-eyebrow">TRACED INDICATOR</span><h2>{trace.ioc}</h2><p className="priority-ip">{trace.report.hosting}</p><div className="evidence-classification"><span>{trace.report.malware.length} MALWARE FAMILIES</span>{trace.report.subdomains.length > 0 && <span>{trace.report.subdomains.length} MALICIOUS SUBDOMAINS</span>}{trace.report.transfers.length > 0 && <span>CRYPTO MONEY TRAIL</span>}{trace.report.consignment && <span>CONSIGNMENT {trace.report.consignment.id}</span>}</div><p className="evidence-summary">{trace.comms.map(d=>`${d.name}: ${d.city}, ${d.country}`).join(" · ")}</p></div> : <div className="priority-evidence"><span className="section-eyebrow">HIGHEST-RISK ASSET</span><h2>{priority?.device.hostname ?? priority?.device.ip ?? "Awaiting assessment"}</h2>{priority && <p className="priority-ip">{priority.device.ip ?? priority.device.node_id}</p>}{cve && <span className="evidence-cve">{cve}</span>}{priorityEvidence && <div className="evidence-classification">{/CISA KEV/i.test(priorityEvidence) && <span>CISA KEV</span>}{/actively exploited/i.test(priorityEvidence) && <span>ACTIVELY EXPLOITED</span>}</div>}{priorityEvidence && <p className="evidence-summary">{priorityEvidence}</p>}</div>}
        <div className="threat-actions">{priority && <button ref={inspectButton} className="btn inspect-command" onClick={()=>setSelected(priority.device.node_id)}>Inspect device <span aria-hidden="true">&#8599;</span></button>}<Link className="response-command" to={priority ? `/devices/${priority.device.node_id}` : "/response"}>Review response <span aria-hidden="true">&#8594;</span></Link></div>
      </aside>
    </div>
    {trace && <section className="panel p-3" aria-label="Devices in active communication"><div className="command-section-title"><div><span className="section-eyebrow">ACTIVE COMMUNICATIONS / {trace.ioc}</span><h2>Devices in active communication</h2></div></div><Suspense fallback={null}><CommsDeviceTable key={trace.ioc} scenario={trace} selected={traceSel} onSelect={(id)=>setTraceSel(s=>s===id?null:id)} /></Suspense></section>}
    <nav className="investigation-path" aria-label="Investigation workflow"><span className="path-label">INVESTIGATION PATH</span><button onClick={()=>priority && setSelected(priority.device.node_id)} disabled={!priority}><b>01</b> Threat</button><span aria-hidden="true">/</span><button onClick={()=>{setSelected(null);document.querySelector('.hero-network')?.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});}}><b>02</b> Network</button><span aria-hidden="true">/</span><Link to={priority ? `/devices/${priority.device.node_id}` : "/devices"}><b>03</b> Device</Link><span aria-hidden="true">/</span><Link to={priority ? `/events?device=${encodeURIComponent(priority.device.node_id)}` : "/events"}><b>04</b> Event</Link><span aria-hidden="true">/</span><Link to="/response"><b>05</b> Response</Link></nav>
    {selectedNode && <div className="overview-inspection"><Inspector node={selectedNode} role={role} dryRun={health?.dry_run ?? true} onClose={()=>{setSelected(null);inspectButton.current?.focus();}} /></div>}
    <div className="command-telemetry"><ThreatActivity events={state.events} rate={rate} /><AssetPosture nodes={nodes} />
      <section className="panel incident-stream"><div className="command-section-title"><div><span className="section-eyebrow">03 / EVENT INTELLIGENCE</span><h2>Incident stream</h2></div><Link to="/events" className="text-signal">View all &#8599;</Link></div>
        <ul>{latest.map(e=>{const n=e.node_id ? state.nodes[e.node_id] : undefined;const color=e.type === "THREAT_CORRELATED" ? "#ff315a" : e.type === "RISK_UPDATED" ? "#ffc928" : e.type === "DEVICE_RESTORED" ? "#19d89a" : "#00d9ff";return <li key={e.seq} style={{"--event-tone":color} as CSSProperties}><Link to={e.node_id ? `/events?device=${encodeURIComponent(e.node_id)}` : "/events"}><span className="incident-time">{new Date(e.ts).toLocaleTimeString([],{hour12:false})}</span><span className="incident-type">{e.type.replace(/_/g," ")}</span><strong>{n?.device.hostname ?? n?.device.ip ?? "System"}</strong><p>{summarize(e)}</p></Link></li>;})}{!latest.length && <li className="telemetry-empty">No events in the current buffer.</li>}</ul>
      </section>
    </div>
    <div className="overview-secondary"><Legend /><dl><div><dt>High risk</dt><dd>{nodes.filter(n=>n.level === "high").length}</dd></div><div><dt>Quarantined</dt><dd>{nodes.filter(n=>n.quarantined).length}</dd></div><div><dt>Unknown trust</dt><dd>{nodes.filter(n=>n.device.trust === "unknown").length}</dd></div><div><dt>Event buffer</dt><dd>{state.events.length}</dd></div></dl></div>
  </div>;
}
