import { Canvas, useFrame, type ThreeEvent } from "@react-three/fiber";
import { Html, OrbitControls } from "@react-three/drei";
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
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
}

/** Live 3D network: the DSN gateway at the centre, every device linked to it.
 * Colour = risk level (magenta = quarantined, its link cut and dashed); size =
 * risk score; a pulse marks recent activity and quarantined devices keep
 * pulsing. Positions update imperatively each frame, so motion never re-renders
 * React. */
export function Graph3D({ nodes, selected, onSelect }: Props) {
  return (
    <Canvas
      camera={{ position: [0, 8, 15], fov: 50 }}
      dpr={[1, 2]}
      gl={{ antialias: true, powerPreference: "high-performance" }}
      onPointerMissed={() => onSelect(null)}
    >
      <color attach="background" args={["#05080d"]} />
      <fog attach="fog" args={["#05080d", 18, 42]} />
      <ambientLight intensity={0.45} />
      <pointLight position={[0, 6, 0]} intensity={60} color={SIGNAL_COLOR} />
      <pointLight position={[10, 12, 10]} intensity={80} />
      <Scene nodes={nodes} selected={selected} onSelect={onSelect} />
      <gridHelper args={[40, 40, "#1d2939", "#0e1520"]} position={[0, -4, 0]} />
      <OrbitControls enableDamping dampingFactor={0.08} minDistance={6} maxDistance={40} />
    </Canvas>
  );
}

function Scene({ nodes, selected, onSelect }: Props) {
  const layout = useRef(new Map<string, LayoutNode>([[HUB, makeNode(HUB, [0, 0, 0])]]));
  const settled = useRef(false);
  const ids = useMemo(() => Object.keys(nodes).sort(), [nodes]);

  // Keep the layout's node set in sync; existing nodes keep their positions.
  useLayoutEffect(() => {
    const map = layout.current;
    const wanted = new Set(ids);
    for (const id of ids) if (!map.has(id)) map.set(id, makeNode(id));
    for (const id of [...map.keys()]) if (id !== HUB && !wanted.has(id)) map.delete(id);
    settled.current = false;
  }, [ids]);

  const edges = useMemo(() => ids.map((id) => [HUB, id] as [string, string]), [ids]);
  const links = useRef<THREE.LineSegments>(null);
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
    const cut = new THREE.Color("#3b1d40");
    ids.forEach((id, i) => {
      const c = nodes[id]?.quarantined ? cut : live;
      colors.set([c.r, c.g, c.b, c.r, c.g, c.b], i * 6);
    });
    const attr = links.current?.geometry.getAttribute("color");
    if (attr) attr.needsUpdate = true;
  }, [ids, nodes, colors]);

  useFrame(() => {
    if (!settled.current) {
      const energy = step([...layout.current.values()], edges);
      if (energy < 1e-4) settled.current = true;
    }
    for (const [id, group] of groups.current) {
      const n = layout.current.get(id);
      if (n) group.position.set(n.pos[0], n.pos[1], n.pos[2]);
    }
    ids.forEach((id, i) => {
      const n = layout.current.get(id);
      if (n) positions.set([0, 0, 0, n.pos[0], n.pos[1], n.pos[2]], i * 6);
    });
    const attr = links.current?.geometry.getAttribute("position");
    if (attr) attr.needsUpdate = true;
  });

  return (
    <>
      <Hub />
      <lineSegments ref={links} frustumCulled={false}>
        <bufferGeometry />
        <lineBasicMaterial vertexColors transparent opacity={0.9} />
      </lineSegments>
      {ids.map((id) => {
        const state = nodes[id];
        return state ? (
        <DeviceNode
          key={id}
          state={state}
          selected={id === selected}
          onSelect={onSelect}
          groups={groups.current}
        />
        ) : null;
      })}
    </>
  );
}

function Hub() {
  const mesh = useRef<THREE.Mesh>(null);
  useFrame((_, dt) => {
    if (mesh.current) mesh.current.rotation.y += dt * 0.4;
  });
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
      <Html center position={[0, -1.3, 0]} style={{ pointerEvents: "none" }}>
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
}

const DeviceNode = memo(function DeviceNode({ state, selected, onSelect, groups }: NodeProps) {
  const id = state.device.node_id;
  const register = useCallback(
    (g: THREE.Group | null) => {
      if (g) groups.set(id, g);
      else groups.delete(id);
    },
    [groups, id],
  );
  const ring = useRef<THREE.Mesh>(null);
  const body = useRef<THREE.MeshStandardMaterial>(null);
  const [hover, setHover] = useState(false);
  const color = nodeColor(state.level, state.quarantined);
  const radius = 0.32 + ((state.score ?? 0) / 100) * 0.45;
  const label = state.device.hostname ?? state.device.ip ?? state.device.node_id.slice(0, 10);

  useFrame(({ clock }) => {
    const age = Date.now() - state.flashAt;
    const active = state.quarantined || age < FLASH_MS;
    const t = clock.getElapsedTime();
    if (ring.current) {
      ring.current.visible = active;
      const phase = (t * 1.4) % 1;
      ring.current.scale.setScalar(1 + phase * 1.6);
      (ring.current.material as THREE.MeshBasicMaterial).opacity = (1 - phase) * 0.7;
    }
    if (body.current) {
      body.current.emissiveIntensity = active ? 0.55 + 0.35 * Math.sin(t * 6) : selected ? 0.5 : 0.22;
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
      {selected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[radius * 1.7, 0.03, 8, 64]} />
          <meshBasicMaterial color="#dce6f2" />
        </mesh>
      )}
      <Html
        center
       
        position={[0, radius + 0.55, 0]}
        style={{ pointerEvents: "none" }}
        zIndexRange={[10, 0]}
      >
        <div
          className={`rounded px-1.5 py-0.5 text-[10px] whitespace-nowrap ${
            selected || hover ? "bg-ink-800/95 text-ink-100" : "text-ink-300"
          }`}
        >
          {label}
          {state.score !== null && (selected || hover) && (
            <span className="ml-1.5 font-mono" style={{ color }}>
              {state.score.toFixed(0)}
            </span>
          )}
          {state.quarantined && <span className="ml-1.5 text-quarantine">⛔</span>}
        </div>
      </Html>
    </group>
  );
});
