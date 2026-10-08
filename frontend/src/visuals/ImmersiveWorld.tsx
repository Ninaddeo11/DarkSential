import { useEffect, useMemo, useRef, useState, type RefObject, type CSSProperties } from 'react';
import { Html } from '@react-three/drei';
import { useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import type { IntelligenceEdge, IntelligenceNode, SceneMode } from './model';

const COLORS: Record<string,string> = {weapons:'#fa5c70',narcotics:'#c390fb',malware:'#b382ff',identities:'#45dce9',crypto:'#659bff',trafficking:'#ff9764',exploits:'#fa5c70',infrastructure:'#4dadd6'};
const META: Record<string,string> = {weapons:'THREAT CATEGORY',narcotics:'FORENSIC EVIDENCE',malware:'IOC / C2 / ATT&CK',identities:'ID / HASH / CREDENTIAL',crypto:'WALLET / FLOW',trafficking:'ABSTRACT ASSOCIATIONS',exploits:'CVE-XXXX-XXXX',infrastructure:'HOST / RELAY / SERVICE'};
type Vec = [number,number,number];
interface Props {mode:SceneMode;nodes:IntelligenceNode[];edges:IntelligenceEdge[];selected?:string|null;onSelect:(id:string)=>void;reduced:boolean;compact:boolean;interactive:boolean;labels:RefObject<HTMLDivElement>;mobile:boolean;}

/** Procedural forensic holograms. All motion and coordinates are illustrative. */
export function ImmersiveWorld({mode,nodes,edges,selected,onSelect,reduced,compact,interactive,labels,mobile}:Props) {
  const {camera,pointer,size,gl,invalidate}=useThree();
  const root=useRef<THREE.Group>(null);
  const scroll=useRef(0);
  const time=useRef(0);
  const engaged=useRef(false);
  const miniature=mode==='evidence';
  useEffect(()=>{
    const card=gl.domElement.closest('.scope-card');
    if(!card)return;
    const enter=()=>{engaged.current=true;};
    const leave=()=>{engaged.current=false;};
    card.addEventListener('pointerenter',enter);card.addEventListener('pointerleave',leave);
    card.addEventListener('focusin',enter);card.addEventListener('focusout',leave);
    return ()=>{card.removeEventListener('pointerenter',enter);card.removeEventListener('pointerleave',leave);card.removeEventListener('focusin',enter);card.removeEventListener('focusout',leave);};
  },[gl]);
  const shown=useMemo(()=>{
    const subset=nodes.slice(0,miniature?1:mobile&&mode==='ecosystem'?4:12);
    const focus=nodes.find(n=>n.id===selected);
    if(mobile&&mode==='ecosystem'&&focus&&!subset.includes(focus))subset[subset.length-1]=focus;
    return subset;
  },[nodes,miniature,mobile,mode,selected]);
  const positions=useMemo(()=>new Map(shown.map((n,i)=>{
    const angle=i/Math.max(1,shown.length)*Math.PI*2+.25;
    const p:Vec=miniature?[0,0,0]:mode==='routes'?[-4.3+i*8.6/Math.max(1,shown.length-1),Math.sin(i*1.7)*1.4,Math.cos(i)*1.1]:mode==='terrain'?[Math.cos(angle)*4.4,Math.sin(angle)*1.8+.2,Math.sin(angle)*.65]:[Math.cos(angle)*4.25,Math.sin(angle)*2.3,Math.sin(angle*2)*1.15];
    return [n.id,new THREE.Vector3(...p)] as const;
  })),[shown,miniature,mode]);
  const bases=useMemo(()=>new Map([...positions].map(([id,p])=>[id,p.clone()])),[positions]);
  useEffect(()=>{
    const host=gl.domElement.closest('.public-main');
    const update=()=>{const frame=gl.domElement.closest('.nexus-scene');if(frame&&host){const box=frame.getBoundingClientRect();scroll.current=THREE.MathUtils.clamp((host.getBoundingClientRect().top-box.top)/Math.max(1,box.height),0,1);}};
    host?.addEventListener('scroll',update,{passive:true});update();
    return ()=>host?.removeEventListener('scroll',update);
  },[gl]);
  useEffect(()=>{
    const aspect=size.width/Math.max(1,size.height);
    const z=miniature?3.5:mode==='routes'?Math.max(6.5,10.8/aspect):Math.max(13.8,11.5/aspect);
    camera.position.set(0,miniature?.55:mode==='routes'?1.8:2.7,z);camera.lookAt(0,0,0);camera.updateProjectionMatrix();invalidate();
  },[camera,size,invalidate,miniature,mode]);
  useFrame((_,dt)=>{
    if(reduced)return;
    time.current+=Math.min(dt,.04);
    const t=time.current;
    if(root.current){root.current.rotation.y=miniature?0:Math.sin(t*.08)*.13+pointer.x*.035;root.current.rotation.x=THREE.MathUtils.damp(root.current.rotation.x,pointer.y*.035,3,dt);}
    const aspect=size.width/Math.max(1,size.height);
    const z=miniature?3.5:mode==='routes'?Math.max(6.5,10.8/aspect):Math.max(13.8,11.5/aspect);
    camera.position.x=THREE.MathUtils.damp(camera.position.x,pointer.x*(mobile?.1:.5)+(mode==='terrain'?Math.sin(t*.09)*.45:0),2,dt);
    camera.position.y=THREE.MathUtils.damp(camera.position.y,(miniature?.55:mode==='routes'?1.8:2.7)+pointer.y*.15+scroll.current*.35,2,dt);
    camera.position.z=THREE.MathUtils.damp(camera.position.z,z-scroll.current*.85,2,dt);camera.lookAt(0,0,0);
    shown.forEach((n,i)=>{const p=positions.get(n.id)!,b=bases.get(n.id)!;const a=mode==='ecosystem'?t*.016:0;const x=b.x*Math.cos(a)-b.y*1.85*Math.sin(a),y=b.x/1.85*Math.sin(a)+b.y*Math.cos(a);p.set(x,y+Math.sin(t*.55+i*1.9)*(miniature?.08:.14),b.z);});
  });
  const pairs=useMemo(()=>mode==='ecosystem'?shown.map(n=>[new THREE.Vector3(),positions.get(n.id)!] as const):edges.flatMap(e=>{const a=positions.get(e.source),b=positions.get(e.target);return a&&b?[[a,b] as const]:[];}),[mode,shown,positions,edges]);
  return <>
    <fog attach="fog" args={['#03070d',12,30]} />
    <pointLight position={[-4,2,1]} intensity={7} color="#315fa7" />
    <group ref={root}>
      {!miniature&&mode!=='routes'&&mode!=='terrain'&&<NexusCore reduced={reduced} mobile={mobile} />}
      {!miniature&&<SignalPaths pairs={pairs} reduced={reduced} color={mode==='routes'?'#ff9764':'#3e9fac'} />}
      {shown.map((node,i)=><Hologram key={node.id} node={node} position={positions.get(node.id)!} index={i} reduced={reduced} miniature={miniature} selected={selected===node.id} labels={labels} interactive={interactive} compact={compact} onSelect={onSelect} engaged={engaged} />)}
    </group>
    {!miniature&&<><Atmosphere reduced={reduced} mobile={mobile} terrain={mode==='terrain'} /><Radar reduced={reduced} /><gridHelper args={[32,mobile?24:40,'#153745','#0c202e']} position={[0,-2.8,0]} /></>}
    <Glow position={[0,miniature?0:-.6,-1]} color="#087a9c" scale={miniature?2:7} opacity={.13} />
  </>;
}

function NexusCore({reduced,mobile}:{reduced:boolean;mobile:boolean}) {
  const core=useRef<THREE.Group>(null);
  const ring=useRef<THREE.Group>(null);
  useFrame((_,dt)=>{if(reduced)return;if(core.current)core.current.rotation.y+=Math.min(dt,.04)*.1;if(ring.current)ring.current.rotation.z-=Math.min(dt,.04)*.065;});
  return <group>
    <group ref={core} rotation={[.18,0,.18]}>
      <mesh><icosahedronGeometry args={[1.68,mobile?2:3]} /><meshBasicMaterial wireframe color="#30a6bc" transparent opacity={.3} /></mesh>
      <mesh><icosahedronGeometry args={[1.58,1]} /><meshBasicMaterial color="#061822" transparent opacity={.78} /></mesh>
      <mesh><icosahedronGeometry args={[1.15,1]} /><meshBasicMaterial wireframe color="#62e9ef" transparent opacity={.26} /></mesh>
      <mesh><octahedronGeometry args={[.7]} /><meshBasicMaterial wireframe color="#92f6ff" transparent opacity={.85} /></mesh>
    </group>
    <group ref={ring} rotation={[.4,.3,.25]}>{[1.93,2.12,2.28].map((r,i)=><mesh key={r} rotation={[i*.7,i*.65,0]}><torusGeometry args={[r,.008,4,96]} /><meshBasicMaterial color={i===2?'#4d6dac':'#40c7d7'} transparent opacity={.32} /></mesh>)}</group>
    <mesh rotation={[-Math.PI/2,0,0]} position={[0,-2.75,0]}><ringGeometry args={[2.1,2.12,96]} /><meshBasicMaterial color="#2699b0" transparent opacity={.55} side={THREE.DoubleSide} /></mesh>
    <Glow color="#47e5f3" scale={1.2} opacity={.24} />
  </group>;
}

/** Recognizable category-specific geometry; no downloaded models or textures. */
function ThreatShape({id,kind,color,reduced}:{id:string;kind:string;color:string;reduced:boolean}) {
  const material=<meshBasicMaterial color={color} wireframe transparent opacity={.85} />;
  if(id==='weapons')return <group rotation={[0,0,-.2]}>
    <mesh position={[-.04,.15,0]}><boxGeometry args={[1.25,.2,.18]} />{material}</mesh>
    <mesh position={[-.47,-.13,0]} rotation={[0,0,-.26]}><boxGeometry args={[.23,.55,.2]} />{material}</mesh>
    <mesh position={[.36,.12,0]}><boxGeometry args={[.52,.12,.14]} />{material}</mesh>
    <mesh position={[-.18,-.08,0]}><torusGeometry args={[.13,.018,4,8,Math.PI]} />{material}</mesh>
  </group>;
  if(id==='narcotics')return <group>
    <mesh><cylinderGeometry args={[.32,.32,.85,8,1,true]} />{material}</mesh>
    {[-.45,.45].map(y=><mesh key={y} position={[0,y,0]}><cylinderGeometry args={[.35,.35,.06,8]} />{material}</mesh>)}
    {[0,1,2].map(i=><mesh key={i} position={[(i-1)*.14,-.13+i*.09,0]} rotation={[.2,i,.3]}><octahedronGeometry args={[.22,0]} />{material}</mesh>)}
  </group>;
  if(kind==='Identity')return <group>
    <mesh position={[0,.35,0]}><icosahedronGeometry args={[.26,1]} />{material}</mesh>
    <mesh position={[0,-.13,0]} scale={[1.25,1,.65]}><cylinderGeometry args={[.16,.42,.5,8,2,true]} />{material}</mesh>
    {[-.3,-.1,.1].map(y=><mesh key={y} position={[0,y,.1]}><boxGeometry args={[.8,.008,.35]} /><meshBasicMaterial color={color} transparent opacity={.25} /></mesh>)}
  </group>;
  if(kind==='Network'||kind==='Ledger')return <LocalNetwork color={color} ledger={kind==='Ledger'} reduced={reduced} />;
  if(kind==='Infrastructure')return <group>{[-1,0,1].map((x,i)=><group key={x} position={[x*.32,(i%2)*.18,0]}><mesh><boxGeometry args={[.22,.7,.28]} />{material}</mesh>{[-.2,0,.2].map(y=><mesh key={y} position={[0,y,.15]}><boxGeometry args={[.15,.025,.01]} /><meshBasicMaterial color={color} /></mesh>)}</group>)}</group>;
  if(kind==='Vulnerability')return <group>{[0,1,2,3].map(i=><mesh key={i} position={[Math.cos(i*1.57)*.24,Math.sin(i*1.57)*.24,0]} rotation={[i*.8,i,0]}><icosahedronGeometry args={[.29,0]} />{material}</mesh>)}<Glow color={color} scale={.8} opacity={.3} /></group>;
  return <group><mesh><icosahedronGeometry args={[.34,0]} />{material}</mesh>{[0,1,2].map(i=><mesh key={i} rotation={[i*.9,.4,i]}><torusGeometry args={[.5+i*.055,.012,4,32]} />{material}</mesh>)}{[0,1,2,3].map(i=><mesh key={i} position={[Math.cos(i*1.57)*.65,Math.sin(i*1.57)*.65,0]} rotation={[i,i,.4]}><boxGeometry args={[.11,.11,.11]} />{material}</mesh>)}<Glow color={color} scale={1.2} opacity={.2} /></group>;
}

function LocalNetwork({color,ledger,reduced}:{color:string;ledger:boolean;reduced:boolean}) {
  const vertices=useMemo(()=>Array.from({length:ledger?5:7},(_,i)=>new THREE.Vector3(Math.sin(i*2.3)*.65,Math.cos(i*1.8)*.45,Math.sin(i)*.25)),[ledger]);
  const pairs=useMemo(()=>vertices.slice(1).map((p,i)=>[vertices[i]!,p] as const).concat([[vertices[0]!,vertices[vertices.length-1]!] as const]),[vertices]);
  return <group>{vertices.map((p,i)=><mesh key={i} position={p}>{ledger?<boxGeometry args={[.22,.22,.22]} />:<icosahedronGeometry args={[.09,0]} />}<meshBasicMaterial color={color} wireframe={ledger} /></mesh>)}<SignalPaths pairs={pairs} reduced={reduced} color={color} local /></group>;
}

function Hologram({node,position,index,reduced,miniature,selected,labels,interactive,compact,onSelect,engaged}:{node:IntelligenceNode;position:THREE.Vector3;index:number;reduced:boolean;miniature:boolean;selected:boolean;labels:RefObject<HTMLDivElement>;interactive:boolean;compact:boolean;onSelect:(id:string)=>void;engaged:RefObject<boolean>}) {
  const group=useRef<THREE.Group>(null);
  const shape=useRef<THREE.Group>(null);
  const halo=useRef<THREE.Mesh>(null);
  const scan=useRef<THREE.Mesh>(null);
  const [hover,setHover]=useState(false);
  const phase=useRef(index*1.7);
  const color=COLORS[node.id]??node.color??'#62b9d1';
  useFrame((_,dt)=>{
    if(group.current)group.current.position.copy(position);
    if(reduced)return;
    phase.current+=Math.min(dt,.04);
    const active=hover||(miniature&&engaged.current);
    if(shape.current){shape.current.rotation.y+=Math.min(dt,.04)*(active?.65:.12+index*.014);shape.current.scale.setScalar(THREE.MathUtils.damp(shape.current.scale.x,active||selected?1.15:1,4,dt));}
    if(halo.current)halo.current.scale.setScalar(1+Math.sin(phase.current*1.2)*.08);
    if(scan.current)scan.current.position.y=.58-((phase.current*.22)%1)*1.15;
  });
  return <group ref={group} position={position}>
    <group ref={shape} onPointerOver={e=>{e.stopPropagation();setHover(true);}} onPointerOut={()=>setHover(false)} onClick={e=>{e.stopPropagation();if(interactive)onSelect(node.id);}}>
      <ThreatShape id={node.id} kind={node.kind} color={color} reduced={reduced} />
      <mesh visible={false}><sphereGeometry args={[.85,8,8]} /><meshBasicMaterial /></mesh>
    </group>
    {node.kind==='Identity'&&<mesh ref={scan} position={[0,.2,0]}><boxGeometry args={[.85,.012,.42]} /><meshBasicMaterial color={color} transparent opacity={.6} depthWrite={false} /></mesh>}
    <mesh ref={halo} rotation={[-Math.PI/2,0,0]} position={[0,-.55,0]}><ringGeometry args={[.63,.645,32]} /><meshBasicMaterial color={color} transparent opacity={hover||selected?.8:.22} side={THREE.DoubleSide} /></mesh>
    {!miniature&&!compact&&<Html center portal={labels} position={[0,-.92,0]} zIndexRange={[9,0]}><button type="button" className={`hologram-label ${selected?'is-selected':''}`} style={{'--threat-color':color} as CSSProperties} onClick={()=>onSelect(node.id)} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}><strong>{node.label}</strong><span>{META[node.id]??'ILLUSTRATIVE ENTITY'}</span></button></Html>}
  </group>;
}

function SignalPaths({pairs,reduced,color,local=false}:{pairs:ReadonlyArray<readonly[THREE.Vector3,THREE.Vector3]>;reduced:boolean;color:string;local?:boolean}) {
  const lines=useRef<THREE.LineSegments>(null);
  const points=useRef<THREE.Points>(null);
  const t=useRef(0);
  const coords=useMemo(()=>new Float32Array(pairs.length*6),[pairs]);
  const dots=useMemo(()=>new Float32Array(pairs.length*3),[pairs]);
  pairs.forEach(([a,b],i)=>{a.toArray(coords,i*6);b.toArray(coords,i*6+3);a.clone().lerp(b,.4).toArray(dots,i*3);});
  useFrame((_,dt)=>{if(reduced)return;t.current+=Math.min(dt,.04);pairs.forEach(([a,b],i)=>{a.toArray(coords,i*6);b.toArray(coords,i*6+3);const f=(t.current*(local?.25:.14)+i*.19)%1;dots[i*3]=a.x+(b.x-a.x)*f;dots[i*3+1]=a.y+(b.y-a.y)*f;dots[i*3+2]=a.z+(b.z-a.z)*f;});if(lines.current)lines.current.geometry.attributes.position!.needsUpdate=true;if(points.current)points.current.geometry.attributes.position!.needsUpdate=true;});
  return <><lineSegments ref={lines} frustumCulled={false}><bufferGeometry><bufferAttribute attach="attributes-position" args={[coords,3]} /></bufferGeometry><lineBasicMaterial color={color} transparent opacity={local?.45:.22} /></lineSegments><points ref={points} frustumCulled={false}><bufferGeometry><bufferAttribute attach="attributes-position" args={[dots,3]} /></bufferGeometry><pointsMaterial color={color} size={local?.04:.065} sizeAttenuation transparent opacity={.9} depthWrite={false} /></points></>;
}

function Atmosphere({reduced,mobile,terrain}:{reduced:boolean;mobile:boolean;terrain:boolean}) {
  const ref=useRef<THREE.Points>(null);
  const geo=useMemo(()=>{
    const count=mobile?70:200, coords=new Float32Array(count*3);
    for(let i=0;i<count;i++){const x=Math.sin(i*127.1)*11,z=Math.cos(i*311.7)*9;coords.set([x,terrain?-2.3+Math.sin(x*.6)*Math.cos(z*.7)*1.1:Math.sin(i*17.3)*3,z],i*3);}
    return coords;
  },[mobile,terrain]);
  const terrainGeometry=useMemo(()=>{const g=new THREE.PlaneGeometry(24,18,mobile?20:36,mobile?16:24);g.rotateX(-Math.PI/2);const a=g.attributes.position!;for(let i=0;i<a.count;i++)a.setY(i,Math.sin(a.getX(i)*.6)*Math.cos(a.getZ(i)*.7)*1.1);g.computeVertexNormals();return g;},[mobile]);
  useEffect(()=>()=>terrainGeometry.dispose(),[terrainGeometry]);
  useFrame((_,dt)=>{if(ref.current&&!reduced)ref.current.rotation.y+=Math.min(dt,.04)*.009;});
  return <><points ref={ref}><bufferGeometry><bufferAttribute attach="attributes-position" args={[geo,3]} /></bufferGeometry><pointsMaterial color="#4d849d" size={.025} transparent opacity={.55} depthWrite={false} /></points>{terrain&&<mesh geometry={terrainGeometry} position={[0,-2.3,0]}><meshBasicMaterial color="#285269" wireframe transparent opacity={.24} /></mesh>}</>;
}

function Radar({reduced}:{reduced:boolean}) {
  const ref=useRef<THREE.Group>(null);
  useFrame((_,dt)=>{if(ref.current&&!reduced)ref.current.rotation.y-=Math.min(dt,.04)*.18;});
  return <group ref={ref} position={[0,-2.76,0]}><mesh rotation={[-Math.PI/2,0,0]}><circleGeometry args={[5.5,32,0,.25]} /><meshBasicMaterial color="#24bace" transparent opacity={.035} side={THREE.DoubleSide} depthWrite={false} /></mesh><mesh rotation={[-Math.PI/2,0,0]}><ringGeometry args={[4.7,4.71,96]} /><meshBasicMaterial color="#258697" transparent opacity={.22} side={THREE.DoubleSide} /></mesh></group>;
}

function Glow({position=[0,0,0],color,scale,opacity}:{position?:Vec;color:string;scale:number;opacity:number}) {
  const map=useMemo(()=>{const data=new Uint8Array(32*32*4);for(let y=0;y<32;y++)for(let x=0;x<32;x++){const i=(y*32+x)*4,r=Math.hypot((x-15.5)/15.5,(y-15.5)/15.5);data[i]=data[i+1]=data[i+2]=255;data[i+3]=Math.round(Math.max(0,1-r)**3*255);}const texture=new THREE.DataTexture(data,32,32);texture.needsUpdate=true;return texture;},[]);
  useEffect(()=>()=>map.dispose(),[map]);
  return <sprite position={position} scale={[scale,scale,1]}><spriteMaterial map={map} color={color} transparent opacity={opacity} blending={THREE.AdditiveBlending} depthWrite={false} /></sprite>;
}
