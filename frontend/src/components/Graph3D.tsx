import { Canvas, useFrame, useThree, type ThreeEvent } from "@react-three/fiber";
import { Html, OrbitControls } from "@react-three/drei";
import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type RefObject,
} from "react";
import type { OrbitControls as OrbitControlsImpl } from "three-stdlib";
import * as THREE from "three";
import type { NodeState } from "../live/store";
import { makeNode, step, type LayoutNode } from "../viz/layout";
import { nodeColor, SIGNAL_COLOR } from "../viz/colors";

const HUB = "__gateway__";
const FLASH_MS = 2500;

interface Props {
  nodes: Record<string, NodeState>;
  selected: string | null;
  onSelect: (nodeId: string | null) => void;
  evidence?: Record<string, string>;
  live?: boolean;
}

/** Live 3D network: the DSN gateway at the centre, every device linked to it.
 * Colour = risk level (red = quarantined, its link cut and dashed); size =
 * risk score; a pulse marks recent activity and quarantined devices keep
 * pulsing. Positions update imperatively each frame, so motion never re-renders
 * React. */
export function Graph3D({ nodes, selected, onSelect, evidence = {}, live = false }: Props) {
  // Labels (drei <Html>) render into this layer, which Graph3D owns. By default
  // they attach to a wrapper react-three-fiber removes first on unmount, which
  // threw "removeChild: not a child of this node" when leaving the page.
  const labels = useRef<HTMLDivElement>(null!);
  const controls = useRef<OrbitControlsImpl>(null);
  const host = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(!document.hidden);
  const [reduced, setReduced] = useState(() => window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    let onscreen = true;
    const update = () => setActive(onscreen && !document.hidden);
    const observer = new IntersectionObserver(([entry]) => { onscreen = !!entry?.isIntersecting; update(); });
    if (host.current) observer.observe(host.current);
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const motion = () => setReduced(media.matches);
    media.addEventListener("change", motion);
    document.addEventListener("visibilitychange", update);
    return () => { observer.disconnect(); media.removeEventListener("change", motion); document.removeEventListener("visibilitychange", update); };
  }, []);
  const [webGL] = useState(() => {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl2");
      if (!gl) return false;
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      return true;
    } catch { return false; }
  });
  if (!webGL) return <NetworkFallback nodes={nodes} selected={selected} onSelect={onSelect} evidence={evidence} live={live} />;
  return (
    <div ref={host} className="relative h-full w-full">
    <Canvas
      camera={{ position: [0, 10, 20], fov: 50 }}
      frameloop={!active ? "never" : reduced ? "demand" : "always"}
      dpr={[1, window.innerWidth < 768 ? 1 : 1.5]}
      gl={{ antialias: true, powerPreference: "high-performance" }}
      onPointerMissed={() => onSelect(null)}
    >
      <color attach="background" args={["#05080C"]} />
      <fog attach="fog" args={["#05080C", 18, 42]} />
      <ambientLight intensity={0.45} />
      <pointLight position={[0, 6, 0]} intensity={60} color={SIGNAL_COLOR} />
      <pointLight position={[10, 12, 10]} intensity={80} />
      <ResponsiveCamera />
      <Scene nodes={nodes} selected={selected} onSelect={onSelect} labels={labels} evidence={evidence} live={live} />
      <gridHelper args={[40, 40, "#182532", "#0B1118"]} position={[0, -4, 0]} />
      <OrbitControls ref={controls} enableDamping dampingFactor={0.08} minDistance={6} maxDistance={40} />
    </Canvas>
    <div className="graph-controls"><button className="btn" aria-label="Zoom in" onClick={() => { controls.current?.dollyIn(1.2); controls.current?.update(); }}>+</button><button className="btn" aria-label="Zoom out" onClick={() => { controls.current?.dollyOut(1.2); controls.current?.update(); }}>-</button></div>
    <div ref={labels} className="pointer-events-none absolute inset-0 overflow-hidden" />
    </div>
  );
}

function ResponsiveCamera() {
  const { camera, size } = useThree();
  useEffect(() => {
    const factor = Math.max(1, 1.6 / (size.width / Math.max(1, size.height)));
    camera.position.set(0, 10 * factor, 20 * factor);
    camera.lookAt(0, 0, 0);
    camera.updateProjectionMatrix();
  }, [camera, size.width, size.height]);
  return null;
}

type Labels = RefObject<HTMLDivElement>;

function Scene({ nodes, selected, onSelect, labels, evidence = {}, live = false }: Props & { labels: Labels }) {
  const layout = useRef(new Map<string, LayoutNode>([[HUB, makeNode(HUB, [0, 0, 0])]]));
  const settled = useRef(false);
  const ids = useMemo(() => Object.keys(nodes).sort(), [nodes]);

  // Keep the layout's node set in sync; existing nodes keep their positions.
  useLayoutEffect(() => {
    const map = layout.current;
    const wanted = new Set(ids);
    for (const id of ids) if (!map.has(id)) map.set(id, makeNode(id));
    for (const id of [...map.keys()]) if (id !== HUB && !wanted.has(id)) map.delete(id);
    // Settle the initial layout without requiring motion frames.
    const initialEdges = ids.map(id => [HUB, id] as [string, string]);
    for (let i = 0; i < 160; i++) if (step([...map.values()], initialEdges) < 1e-4) break;
    settled.current = true;
  }, [ids]);

  const edges = useMemo(() => ids.map((id) => [HUB, id] as [string, string]), [ids]);
  const links = useRef<THREE.LineSegments>(null);
  const particles = useRef<THREE.Points>(null);
  const signalPositions = useMemo(() => new Float32Array(Math.min(ids.length, 32) * 3), [ids]);
  const signalColors = useMemo(() => new Float32Array(Math.min(ids.length, 32) * 3), [ids]);
  const groups = useRef(new Map<string, THREE.Group>());
  // Link buffers are allocated once per node set and updated in place each frame.
  const positions = useMemo(() => new Float32Array(ids.length * 6), [ids]);
  const colors = useMemo(() => new Float32Array(ids.length * 6), [ids]);

  useLayoutEffect(() => {
    const geo = links.current?.geometry;
    if (!geo) return;
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  }, [positions, colors]);

  useEffect(() => {
    const live = new THREE.Color("#1f4a5c");
    const cut = new THREE.Color("#6b2638");
    ids.forEach((id, i) => {
      const c = nodes[id]?.quarantined ? cut : nodes[id]?.level === "critical" ? new THREE.Color("#8e3049") : live;
      colors.set([c.r, c.g, c.b, c.r, c.g, c.b], i * 6);
      if (i < 32) {
        const signal = new THREE.Color(nodeColor(nodes[id]?.level ?? null, false));
        signalColors.set([signal.r, signal.g, signal.b], i * 3);
      }
    });
    const attr = links.current?.geometry.getAttribute("color");
    if (attr) attr.needsUpdate = true;
    const signalAttr = particles.current?.geometry.getAttribute("color");
    if (signalAttr) signalAttr.needsUpdate = true;
  }, [ids, nodes, colors, signalColors]);

  // Emphasize critical assets beside the gateway without changing topology or state.
  const criticalIds = ids.filter(id => nodes[id]?.level === "critical");
  const positionFor = (id: string, n: LayoutNode): [number, number, number] => {
    const index = criticalIds.indexOf(id);
    return index >= 0 ? [6, 1, index * 3] : n.pos;
  };
  useFrame(({ clock }) => {
    if (!settled.current) {
      const energy = step([...layout.current.values()], edges);
      if (energy < 1e-4) settled.current = true;
    }
    for (const [id, group] of groups.current) {
      const n = layout.current.get(id);
      if (n) group.position.set(...positionFor(id, n));
    }
    ids.forEach((id, i) => {
      const n = layout.current.get(id);
      if (n) positions.set([0, 0, 0, ...positionFor(id, n)], i * 6);
    });
    const attr = links.current?.geometry.getAttribute("position");
    if (attr) attr.needsUpdate = true;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    for (let i = 0; i < Math.min(ids.length, 32); i++) {
      const id = ids[i];
      if (!id) continue;
      const n = layout.current.get(id), state = nodes[id];
      const active = live && !reduced && state && Date.now() - state.flashAt < FLASH_MS && !state.quarantined;
      const phase = (clock.getElapsedTime() * (state?.level === "critical" ? .3 : .15) + i * .13) % 1;
      const pos = n && active ? positionFor(id, n) : null;
      signalPositions[i * 3] = pos ? pos[0] * phase : 0;
      signalPositions[i * 3 + 1] = pos ? pos[1] * phase : -1000;
      signalPositions[i * 3 + 2] = pos ? pos[2] * phase : 0;
    }
    if (particles.current) {
      particles.current.geometry.getAttribute("position").needsUpdate = true;
    }
  });

  return (
    <>
      <Hub labels={labels} />
      <lineSegments ref={links} frustumCulled={false}>
        <bufferGeometry />
        <lineBasicMaterial vertexColors transparent opacity={0.9} />
      </lineSegments>
      <points ref={particles} frustumCulled={false}><bufferGeometry><bufferAttribute attach="attributes-position" args={[signalPositions, 3]} /><bufferAttribute attach="attributes-color" args={[signalColors, 3]} /></bufferGeometry><pointsMaterial vertexColors size={.055} transparent opacity={.65} depthWrite={false} /></points>
      {ids.map((id) => {
        const state = nodes[id];
        return state ? (
        <DeviceNode
          key={id}
          state={state}
          evidence={evidence[id]}
          selected={id === selected}
          onSelect={onSelect}
          groups={groups.current}
          labels={labels}
        />
        ) : null;
      })}
    </>
  );
}

function Hub({ labels }: { labels: Labels }) {
  const mesh = useRef<THREE.Mesh>(null);

  return (
    <group>
      <mesh ref={mesh}>
        <octahedronGeometry args={[0.8, 0]} />
        <meshStandardMaterial
          color={SIGNAL_COLOR}
          emissive={SIGNAL_COLOR}
          emissiveIntensity={0.6}
          wireframe
        />
      </mesh>
      <Html center position={[0, -1.3, 0]} style={{ pointerEvents: "none" }} portal={labels}>
        <div className="text-[10px] font-semibold tracking-widest whitespace-nowrap text-signal uppercase">
          DSN gateway
        </div>
      </Html>
    </group>
  );
}

interface NodeProps {
  state: NodeState;
  selected: boolean;
  onSelect: (id: string) => void;
  groups: Map<string, THREE.Group>; // stable registry the scene positions each frame
  labels: Labels;
  evidence?: string;
}

const DeviceNode = memo(function DeviceNode({
  state,
  selected,
  onSelect,
  groups,
  labels,
  evidence,
}: NodeProps) {
  const id = state.device.node_id;
  const register = useCallback(
    (g: THREE.Group | null) => {
      if (g) groups.set(id, g);
      else groups.delete(id);
    },
    [groups, id],
  );
  const ring = useRef<THREE.Mesh>(null);
  const threatRing = useRef<THREE.Mesh>(null);
  const body = useRef<THREE.MeshStandardMaterial>(null);
  const [hover, setHover] = useState(false);
  const color = nodeColor(state.level, state.quarantined);
  const radius = (state.level === "critical" ? 0.72 : 0.4) + ((state.score ?? 0) / 100) * 0.45;
  const label = state.device.hostname ?? state.device.ip ?? state.device.node_id.slice(0, 10);

  useFrame(({ clock, camera }) => {
    if (threatRing.current) threatRing.current.quaternion.copy(camera.quaternion);
    const age = Date.now() - state.flashAt;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const active = state.quarantined || state.level === "critical" || age < FLASH_MS;
    const t = clock.getElapsedTime();
    if (ring.current) {
      ring.current.quaternion.copy(camera.quaternion);
      ring.current.visible = active;
      const phase = reduced ? 0 : (t * 0.35) % 1;
      ring.current.scale.setScalar(1 + phase * 1.6);
      (ring.current.material as THREE.MeshBasicMaterial).opacity = (1 - phase) * 0.7;
    }
    if (body.current) {
      body.current.emissiveIntensity = active ? reduced ? 0.3 : 0.3 + 0.12 * Math.sin(t * 2) : selected ? 0.5 : 0.22;
    }
  });

  const click = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    onSelect(state.device.node_id);
  };

  return (
    <group ref={register}>
      <mesh
        onClick={click}
        onPointerOver={(e) => {
          e.stopPropagation();
          setHover(true);
          document.body.style.cursor = "pointer";
        }}
        onPointerOut={() => {
          setHover(false);
          document.body.style.cursor = "";
        }}
      >
        <sphereGeometry args={[radius, 32, 32]} />
        <meshStandardMaterial
          ref={body}
          color={color}
          emissive={color}
          emissiveIntensity={0.22}
          roughness={0.35}
          metalness={0.2}
        />
      </mesh>
      <mesh ref={ring} rotation={[Math.PI / 2, 0, 0]} visible={false}>
        <ringGeometry args={[radius * 1.25, radius * 1.4, 48]} />
        <meshBasicMaterial color={color} transparent side={THREE.DoubleSide} depthWrite={false} />
      </mesh>
      {state.level === "critical" && <mesh ref={threatRing}><torusGeometry args={[radius * 1.8, .025, 8, 64]} /><meshBasicMaterial color={color} transparent opacity={.65} /></mesh>}
      {selected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[radius * 1.7, 0.03, 8, 64]} />
          <meshBasicMaterial color="#E8F2F7" />
        </mesh>
      )}
      <Html
        center
        portal={labels}
       
        position={[0, state.level === "critical" ? -radius - 1.3 : radius + 0.55, 0]}
        style={{ pointerEvents: "auto" }}
        zIndexRange={[10, 0]}
      >
        <button type="button" onClick={() => onSelect(id)} title={[label, state.device.ip, `Risk ${state.score?.toFixed(1) ?? "unscored"}`, evidence].filter(Boolean).join("\n")}
          className={`graph-node-label ${state.level === "critical" ? "graph-node-critical" : ""} rounded px-1.5 py-0.5 text-[10px] whitespace-nowrap ${
            selected || hover ? "bg-ink-800/95 text-ink-100" : "text-ink-300"
          }`}
        >
          {state.level === "critical" && <span className="node-critical-tag">CRITICAL</span>}
          {label}
          {state.level === "critical" && evidence?.match(/CVE-\d{4}-\d+/i)?.[0] && <span className="node-evidence">{evidence.match(/CVE-\d{4}-\d+/i)?.[0]}</span>}
          {state.score !== null && (selected || hover) && (
            <span className="ml-1.5 font-mono" style={{ color }}>
              {state.score.toFixed(0)}
            </span>
          )}
          {state.quarantined && <span className="ml-1.5 text-quarantine">â›”</span>}
        </button>
      </Html>
    </group>
  );
});

/** Preserve topology inspection on devices without a WebGL context. */
function NetworkFallback({ nodes, selected, onSelect, evidence = {}, live = false }: Props) {
  const all = Object.values(nodes).sort((a,b) => a.device.node_id.localeCompare(b.device.node_id));
  const normal = all.filter(n => n.level !== "critical");
  const [zoom, setZoom] = useState(1);
  return <div className="network-fallback">
    <svg viewBox={`${400 - 400 / zoom} ${250 - 250 / zoom} ${800 / zoom} ${500 / zoom}`} role="img" aria-label="Network topology, compatible view">
      <defs><pattern id="topology-grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#182532" strokeWidth=".5" /></pattern></defs>
      <rect width="800" height="500" fill="url(#topology-grid)" />
      {all.map((n) => {
        const critical = n.level === "critical";
        const index = critical ? all.filter(v=>v.level === "critical").indexOf(n) : normal.indexOf(n);
        const angle = index / Math.max(1,normal.length) * Math.PI * 2 - Math.PI / 2;
        const x = critical ? 620 : 310 + Math.cos(angle) * 215;
        const y = critical ? 215 + index * 95 : 235 + Math.sin(angle) * 145;
        const color = nodeColor(n.level, n.quarantined);
        return <g key={n.device.node_id}>
          <path d={`M310 235L${x} ${y}`} stroke={critical ? "#84304a" : n.quarantined ? color : "#225266"} strokeWidth={critical ? 1.5 : 1} strokeDasharray={n.quarantined ? "4 4" : undefined} />
          {live && Date.now() - n.flashAt < FLASH_MS && !n.quarantined && <circle r="2.5" fill={color} className="signal-particle"><animateMotion dur={critical ? "3s" : "6s"} repeatCount="indefinite" path={`M310 235L${x} ${y}`} /></circle>}
          <g role="button" tabIndex={0} aria-label={`Inspect ${n.device.hostname ?? n.device.ip ?? n.device.node_id}`} onClick={() => onSelect(n.device.node_id)} onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(n.device.node_id); } }} className="fallback-node">
            <title>{[n.device.hostname ?? n.device.node_id,n.device.ip,`Risk ${n.score?.toFixed(1) ?? "unscored"}`,evidence[n.device.node_id]].filter(Boolean).join("\n")}</title>
            {critical && <><circle cx={x} cy={y} r="51" fill="#ff315a06" stroke={color} opacity=".25" /><circle className="threat-wave" cx={x} cy={y} r="40" stroke={color} fill="none" style={{transformOrigin:`${x}px ${y}px`}} /><rect x={x-43} y={y-78} width="86" height="21" rx="3" fill="#ff315a12" stroke="#ff315a55" /><text x={x} y={y-64} textAnchor="middle" fill={color} fontSize="10" letterSpacing="1.5">CRITICAL</text></>}
            <circle cx={x} cy={y} r={critical ? 34 : 18} fill="#0b1118" stroke={color} strokeWidth={selected === n.device.node_id ? 3 : 1} />
            <circle cx={x} cy={y} r="7" fill={color} />
            {n.level === "critical" && <circle cx={x} cy={y} r="42" stroke={color} fill="none" />}
            <text x={x} y={y + (critical ? 64 : 35)} textAnchor="middle" fill="#e8f2f7" fontSize={critical ? 17 : 11} fontWeight={critical ? 600 : 400}>{n.device.hostname ?? n.device.ip ?? n.device.node_id.slice(0, 12)}</text>
            <text x={x} y={y + (critical ? 82 : 50)} textAnchor="middle" fill={color} fontSize="10">{n.level ?? "unscored"}{n.score != null ? ` / ${n.score.toFixed(1)}` : ""}</text>
            {critical && evidence[n.device.node_id]?.match(/CVE-\d{4}-\d+/i)?.[0] && <text x={x} y={y+100} textAnchor="middle" fill="#8ea3b2" fontSize="10">{evidence[n.device.node_id]?.match(/CVE-\d{4}-\d+/i)?.[0]}</text>}
          </g>
        </g>;
      })}
      <path d="M310 208l24 13v28l-24 13-24-13v-28z" fill="#0b1118" stroke="#00d9ff" strokeWidth="2" />
      <text x="310" y="289" textAnchor="middle" fill="#00d9ff" fontSize="11">DSN GATEWAY</text>
    </svg><div className="graph-controls"><button className="btn" aria-label="Zoom in" onClick={() => setZoom(v => Math.min(2, v + .2))}>+</button><button className="btn" aria-label="Zoom out" onClick={() => setZoom(v => Math.max(.6, v - .2))}>-</button></div><p>Compatible topology view / select an asset to inspect</p>
  </div>;
}
