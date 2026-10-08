import { Canvas, useFrame, useThree, type ThreeEvent } from "@react-three/fiber";
import { Html, OrbitControls } from "@react-three/drei";
import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import type { OrbitControls as OrbitControlsImpl } from "three-stdlib";
import * as THREE from "three";
import type { IntelligenceEdge, IntelligenceNode, SceneMode } from "./model";
import { ImmersiveWorld } from "./ImmersiveWorld";

interface Props {
  mode: SceneMode; nodes: IntelligenceNode[]; edges: IntelligenceEdge[];
  selected?: string | null; onSelect: (id: string) => void;
  reduced: boolean; paused: boolean; compact: boolean; interactive: boolean;
}

export function SceneEngine(props: Props) {
  const labels = useRef<HTMLDivElement>(null!);
  const [mobile,setMobile] = useState(() => window.matchMedia("(max-width: 767px)").matches);
  useEffect(()=>{
    const media=window.matchMedia("(max-width: 767px)");
    const update=()=>setMobile(media.matches);
    media.addEventListener('change',update);
    return ()=>media.removeEventListener('change',update);
  },[]);
  const immersive = ['ecosystem','terrain','routes','evidence'].includes(props.mode);
  return <div className="scene-engine">
    <Canvas camera={{position:[0,3,13],fov:45}} dpr={[1,mobile?1:1.5]} frameloop={props.paused ? "never" : props.reduced ? "demand" : "always"} gl={{antialias:true,powerPreference:"low-power",alpha:true}} onCreated={({gl})=>{gl.domElement.addEventListener('webglcontextlost',()=>{gl.domElement.parentElement?.dispatchEvent(new Event('nexus-context-lost',{bubbles:true}));});}}>
      <ambientLight intensity={.7} /><pointLight position={[4,6,5]} intensity={30} color="#00d9ff" />
      {immersive ? <ImmersiveWorld {...props} labels={labels} mobile={mobile} /> : <World {...props} labels={labels} mobile={mobile} />}
    </Canvas>
    <div ref={labels} className="scene-labels" />
  </div>;
}

function World({mode,nodes,edges,selected,onSelect,reduced,compact,interactive,labels,mobile}: Props & { labels: RefObject<HTMLDivElement>; mobile: boolean }) {
  const root=useRef<THREE.Group>(null);
  const controls=useRef<OrbitControlsImpl>(null);
  const {camera,size,pointer}=useThree();
  const shown=nodes.slice(0,mobile?24:36);
  const points=useMemo(()=>{
    const out=new Float32Array((mobile?100:460)*3);
    for(let i=0;i<out.length/3;i++){
      const x=Math.sin(i*29.13)*8,z=Math.cos(i*17.7)*6;
      out.set([x,-2.6 + Math.sin(x*.8)*Math.cos(z*.9)*.35,z],i*3);
    }
    return out;
  },[mobile]);
  const positions=useMemo(()=>new Map(shown.map((n,i)=>{
    const a=i/Math.max(1,shown.length)*Math.PI*2;
    const radius=mode === "globe" ? 4.1 : 3.8 + (i%3)*.4;
    const pos: [number,number,number]=mode === "pipeline" ? [-4.5+i/Math.max(1,shown.length-1)*9,0,0] : [Math.cos(a)*radius,Math.sin(a*2)*.85,Math.sin(a)*radius*.6];
    return [n.id,pos] as const;
  })),[nodes,mode,mobile]);
  const linkGeometry=useMemo(()=>{
    const geo=new THREE.BufferGeometry(),coords:number[]=[];
    for(const e of edges){const a=positions.get(e.source),b=positions.get(e.target);if(a&&b)coords.push(...a,...b);}
    geo.setAttribute("position",new THREE.Float32BufferAttribute(coords,3));return geo;
  },[edges,positions]);
  useEffect(()=>()=>linkGeometry.dispose(),[linkGeometry]);
  useEffect(()=>{
    const factor=Math.max(1,1.7/(size.width/Math.max(1,size.height)));
    camera.position.set(0,2.5,12.5*factor);
    camera.lookAt(0,0,0);camera.updateProjectionMatrix();
  },[camera,size.width,size.height]);
  useEffect(()=>{
    const pos=selected ? positions.get(selected) : undefined;
    if(pos&&controls.current){controls.current.target.set(pos[0]*.45,pos[1]*.45,pos[2]*.45);controls.current.update();}
  },[selected,positions]);
  useFrame(({clock},dt)=>{
    if(!root.current||reduced)return;
    if(mode === "globe" || mode === "specimen"){
      root.current.rotation.y+=Math.min(dt,.05)*.045;
      root.current.rotation.x=THREE.MathUtils.damp(root.current.rotation.x,pointer.y*.07,3,dt);
    }
    if(mode === "scanner")root.current.rotation.y=clock.getElapsedTime()*.06;
  });
  return <>
    <group ref={root}>
      <Core mode={mode} reduced={reduced} />
      <lineSegments geometry={linkGeometry}><lineBasicMaterial color="#2c6475" transparent opacity={.6} /></lineSegments>
      {edges.length > 0 && <EvidenceFlow edges={edges} positions={positions} reduced={reduced} />}
      {shown.map(n=><EvidenceObject key={n.id} node={n} position={positions.get(n.id)!} selected={selected===n.id} onSelect={onSelect} labels={labels} compact={compact} interactive={interactive} reduced={reduced} />)}
      {mode === "globe" && <><mesh rotation={[Math.PI/2,0,.2]}><torusGeometry args={[3.2,.008,4,100]} /><meshBasicMaterial color="#168bff" transparent opacity={.45} /></mesh><mesh rotation={[.8,.2,.4]}><torusGeometry args={[3.6,.006,4,100]} /><meshBasicMaterial color="#a855f7" transparent opacity={.3} /></mesh></>}
    </group>
    <points position={[0,0,0]}><bufferGeometry><bufferAttribute attach="attributes-position" args={[points,3]} /></bufferGeometry><pointsMaterial color="#168bff" size={.018} transparent opacity={.45} depthWrite={false} /></points>
    <gridHelper args={[18,18,"#173443","#0d1e2a"]} position={[0,-2.8,0]} />
    {interactive && <OrbitControls ref={controls} enableDamping={!reduced} enablePan={false} minDistance={6} maxDistance={28} maxPolarAngle={Math.PI*.75} />}
  </>;
}

function Core({mode,reduced}:{mode:SceneMode;reduced:boolean}){
  const ref=useRef<THREE.Group>(null);
  useFrame((_,dt)=>{if(ref.current&&!reduced)ref.current.rotation.y+=Math.min(dt,.05)*.1;});
  if(mode === "pipeline")return null;
  return <group ref={ref}>
    <mesh><icosahedronGeometry args={[mode === "globe"?2:1.3,mode === "globe"?2:1]} /><meshBasicMaterial color="#00d9ff" wireframe transparent opacity={.34} /></mesh>
    <mesh><icosahedronGeometry args={[mode === "globe"?1.94:1.22,1]} /><meshStandardMaterial color="#071019" metalness={.65} roughness={.6} /></mesh>
    <mesh rotation={[Math.PI/2,0,0]}><torusGeometry args={[mode === "globe"?2.25:1.7,.012,4,80]} /><meshBasicMaterial color="#00d9ff" transparent opacity={.6} /></mesh>
    {mode === "specimen"&&<mesh rotation={[.6,.4,.2]}><octahedronGeometry args={[1.85,0]} /><meshBasicMaterial color="#a855f7" wireframe transparent opacity={.55} /></mesh>}
  </group>;
}

function EvidenceObject({node,position,selected,onSelect,labels,compact,interactive,reduced}:{node:IntelligenceNode;position:[number,number,number];selected:boolean;onSelect:(id:string)=>void;labels:RefObject<HTMLDivElement>;compact:boolean;interactive:boolean;reduced:boolean}){
  const object=useRef<THREE.Mesh>(null);
  const color=node.color ?? (node.kind === "Malware" ? "#a855f7" : node.kind === "Vulnerability" ? "#ff9f2d" : "#00d9ff");
  useFrame((_,dt)=>{if(object.current&&!reduced)object.current.rotation.y+=Math.min(dt,.05)*.13;});
  const click=(e:ThreeEvent<MouseEvent>)=>{e.stopPropagation();if(interactive)onSelect(node.id);};
  return <group position={position}>
    <mesh ref={object} onClick={click} scale={selected?1.3:1}>
      {node.kind === "Identity" ? <capsuleGeometry args={[.17,.3,3,8]} /> : node.kind === "Evidence" ? <boxGeometry args={[.5,.35,.4]} /> : node.kind === "Ledger" ? <torusGeometry args={[.24,.055,5,12]} /> : node.kind === "Malware" ? <octahedronGeometry args={[.4,0]} /> : <icosahedronGeometry args={[.3,0]} />}
      <meshStandardMaterial color={color} wireframe metalness={.4} roughness={.5} emissive={color} emissiveIntensity={.15} />
    </mesh>
    {selected && <mesh rotation={[Math.PI/2,0,0]}><torusGeometry args={[.62,.014,4,40]} /><meshBasicMaterial color={color} /></mesh>}
    {!compact&&<Html center portal={labels} position={[0,-.65,0]} zIndexRange={[8,0]}><button type="button" className={`scene-object-label ${selected?"is-selected":""}`} onClick={()=>onSelect(node.id)} title={node.detail ?? node.label}>{node.label.length>22?`${node.label.slice(0,21)}…`:node.label}{node.value!==undefined&&<span>{node.value}</span>}</button></Html>}
  </group>;
}

/** Motion denotes graph traversal; schematic surfaces label the conceptual workflow. */
function EvidenceFlow({edges,positions,reduced}:{edges:IntelligenceEdge[];positions:Map<string,[number,number,number]>;reduced:boolean}) {
  const ref=useRef<THREE.Points>(null);
  const pairs=useMemo(()=>edges.flatMap(e=>{const a=positions.get(e.source),b=positions.get(e.target);return a&&b?[[a,b]]:[];}).slice(0,32),[edges,positions]);
  const coords=useMemo(()=>new Float32Array(pairs.length*3),[pairs]);
  useFrame(({clock})=>{if(reduced)return; pairs.forEach(([a,b],i)=>{const t=(clock.getElapsedTime()*.12+i*.17)%1;for(let j=0;j<3;j++)coords[i*3+j]=a![j]!+(b![j]!-a![j]!)*t;});if(ref.current)ref.current.geometry.getAttribute('position').needsUpdate=true;});
  if(reduced)return null;
  return <points ref={ref} frustumCulled={false}><bufferGeometry><bufferAttribute attach="attributes-position" args={[coords,3]} /></bufferGeometry><pointsMaterial color="#00d9ff" size={.055} transparent opacity={.7} depthWrite={false} /></points>;
}
