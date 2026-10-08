import { Component, lazy, Suspense, useEffect, useRef, useState, type ReactNode } from "react";
import type { IntelligenceEdge, IntelligenceNode, SceneMode } from "./model";

const Engine = lazy(() => import("./SceneEngine").then(m => ({ default: m.SceneEngine })));
let capable: boolean | undefined;
export function supportsWebGL() {
  if (capable !== undefined) return capable;
  try {
    const gl = document.createElement("canvas").getContext("webgl2");
    capable = !!gl;
    gl?.getExtension("WEBGL_lose_context")?.loseContext();
  } catch { capable = false; }
  return capable;
}

export interface NexusSceneProps {
  mode?: SceneMode;
  nodes?: IntelligenceNode[];
  edges?: IntelligenceEdge[];
  selected?: string | null;
  onSelect?: (id: string) => void;
  title: string;
  caption?: string;
  illustrative?: boolean;
  compact?: boolean;
  interactive?: boolean;
  className?: string;
}

/** Shared lazy-loaded, visibility-aware 3D surface and accessible graph projection. */
export function NexusScene({ mode = "network", nodes = [], edges = [], selected, onSelect, title, caption, illustrative = false, compact = false, interactive = true, className = "" }: NexusSceneProps) {
  const host = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [reduced, setReduced] = useState(true);
  const [selection, setSelection] = useState<string | null>(null);
  const [contextLost, setContextLost] = useState(false);
  const current = selected === undefined ? selection : selected;
  const focused = nodes.find(n => n.id === current);
  useEffect(() => {
    const target = host.current;
    if (!target) return;
    const observer = new IntersectionObserver(([entry]) => setVisible(!!entry?.isIntersecting), { rootMargin: "100px" });
    observer.observe(target);
    const onVisibility = () => setHidden(document.hidden);
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onMotion = () => setReduced(media.matches);
    onVisibility();
    onMotion();
    const onContextLost = () => setContextLost(true);
    target.addEventListener('nexus-context-lost', onContextLost);
    document.addEventListener("visibilitychange", onVisibility);
    media.addEventListener("change", onMotion);
    return () => { observer.disconnect(); target.removeEventListener('nexus-context-lost', onContextLost); document.removeEventListener("visibilitychange", onVisibility); media.removeEventListener("change", onMotion); };
  }, []);
  const choose = (id: string) => { setSelection(id); onSelect?.(id); };
  const fallback = <SceneProjection mode={mode} nodes={nodes} edges={edges} selected={current} onSelect={choose} title={title} compact={compact} />;
  return <div ref={host} className={`nexus-scene ${compact ? "scene-compact" : ""} ${className}`}>
    <div className="scene-caption"><span>{caption ?? title}</span><span>{illustrative ? "ILLUSTRATIVE / RESEARCH SCOPE" : nodes.length ? `${nodes.length} VISIBLE OBJECTS` : "PROCEDURAL FORENSIC VISUAL"}</span></div>
    <div className="scene-viewport" role="group" aria-label={title}>
      {visible ? <SceneBoundary key={mode} fallback={<>{fallback}<span className="static-mode">STATIC INTELLIGENCE MODE</span></>}><Suspense fallback={fallback}>{!contextLost&&supportsWebGL() ? <Engine mode={mode} nodes={nodes} edges={edges} selected={current} onSelect={choose} reduced={reduced} paused={hidden} compact={compact} interactive={interactive} /> : <>{fallback}<span className="static-mode">STATIC INTELLIGENCE MODE</span></>}</Suspense></SceneBoundary> : fallback}
    </div>
    {interactive && nodes.length > 0 && <div className="scene-node-controls" aria-label="Select intelligence object">{nodes.slice(0,36).map(n => <button key={n.id} type="button" aria-pressed={current === n.id} onClick={() => choose(n.id)} title={n.label}>{n.label.length > 24 ? `${n.label.slice(0,23)}…` : n.label}</button>)}</div>}
    {focused && interactive && <div className="scene-insight" aria-live="polite"><span className="technical-badge">{focused.kind}</span><strong>{focused.label}</strong>{focused.detail && <p>{focused.detail}</p>}{focused.value !== undefined && <span className="font-mono">{focused.value.toLocaleString()} graph objects</span>}</div>}
  </div>;
}

class SceneBoundary extends Component<{ fallback: ReactNode; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() { return this.state.failed ? this.props.fallback : this.props.children; }
}

function SceneProjection({ mode, nodes, edges, selected, onSelect, title, compact }: { mode: SceneMode; nodes: IntelligenceNode[]; edges: IntelligenceEdge[]; selected?: string | null; onSelect: (id: string) => void; title: string; compact: boolean }) {
  const shown = nodes.slice(0,36);
  const positions = new Map(shown.map((n,i) => {
    const angle = i / Math.max(1,shown.length) * Math.PI * 2;
    const pos: [number,number] = mode === "pipeline" ? [60 + i / Math.max(1,shown.length-1)*580,165] : [350 + Math.cos(angle)*240,165 + Math.sin(angle)*110];
    return [n.id, pos] as const;
  }));
  return <svg viewBox="0 0 700 330" className="scene-projection" role="img" aria-label={`${title}, compatible view`}>
    <defs><pattern id={`scene-grid-${mode}`} width="35" height="35" patternUnits="userSpaceOnUse"><path d="M35 0H0V35" fill="none" stroke="#16303e" strokeWidth=".5" /></pattern></defs>
    <rect width="700" height="330" fill={`url(#scene-grid-${mode})`} />
    <ellipse cx="350" cy="175" rx="200" ry="65" fill="none" stroke="#00d9ff25" /><ellipse cx="350" cy="175" rx="150" ry="100" fill="none" stroke="#00d9ff15" />
    {edges.map((e,i) => { const a=positions.get(e.source),b=positions.get(e.target);return a&&b ? <path key={i} d={`M${a[0]} ${a[1]}L${b[0]} ${b[1]}`} stroke="#254959" strokeWidth="1" /> : null; })}
    <path d="M350 104l52 30v60l-52 30-52-30v-60zM298 134l104 60M402 134l-104 60M350 104v120" fill="#071019" stroke="#00d9ff" strokeWidth="1" />
    {shown.map(n => {const [x,y]=positions.get(n.id)!;return <g key={n.id} role="button" tabIndex={compact ? -1 : 0} aria-label={`Inspect ${n.label}`} onClick={() => onSelect(n.id)} onKeyDown={e=>{if(e.key === "Enter" || e.key === " "){e.preventDefault();onSelect(n.id);}}}><title>{n.detail ?? n.label}</title><circle cx={x} cy={y} r={selected===n.id ? 21 : 14} fill="#071019" stroke={n.color ?? "#00d9ff"} /><path d={`M${x-5} ${y}h10M${x} ${y-5}v10`} stroke={n.color ?? "#00d9ff"} />{!compact&&<text x={x} y={y+30} textAnchor="middle" fill="#8ea3b2" fontSize="9" fontFamily="var(--font-mono)">{n.label.slice(0,24)}</text>}</g>;})}
    {!shown.length && <><circle cx="350" cy="164" r="85" stroke="#168bff40" fill="none" strokeDasharray="2 8" /><path d="M230 164H470M350 44V284" stroke="#00d9ff20" /></>}
  </svg>;
}
