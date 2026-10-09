import { useEffect, useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { BokehPass } from 'three/addons/postprocessing/BokehPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { ThreatObject } from './ThreatObject';
import { visibleArtifacts, type ThreatArtifact, type WorldLayer } from './worldModel';
import type { WorldTier } from './DarkWebEnvironment';

interface Props {layer:WorldLayer;tier:WorldTier;reduced:boolean;paused:boolean;focus:string|null;eventSource:HTMLElement;onHover:(category:string|null)=>void;onFailure:()=>void;onPerformanceDrop:()=>void;}

export function DarkWebWorldEngine(props:Props){
  const camera=useMemo(()=>({position:[0,1,20] as [number,number,number],fov:42,near:.1,far:90}),[]);
  return <Canvas className="persistent-world-canvas" eventSource={props.eventSource} eventPrefix="client" camera={camera} dpr={[1,props.tier==='desktop'?1.35:1]} frameloop={props.paused?'never':props.reduced?'demand':'always'} shadows={props.tier==='desktop'?'percentage':false} gl={{alpha:false,antialias:props.tier!=='mobile',powerPreference:'low-power'}} onCreated={({gl})=>{gl.setClearColor('#02060a',1);gl.toneMapping=THREE.ACESFilmicToneMapping;gl.toneMappingExposure=1.4;}}>
    <color attach="background" args={['#02060a']} /><fog attach="fog" args={['#02060a',18,52]} />
    <SceneLighting tier={props.tier} />
    <EnvironmentLighting onFailure={props.onFailure} />
    <IntelligenceWorld {...props} />
    {props.tier==='desktop'&&<AtmosphericLens reduced={props.reduced} />}
  </Canvas>;
}

function EnvironmentLighting({onFailure}:{onFailure:()=>void}){
  const {gl,scene,invalidate}=useThree();
  useEffect(()=>{
    const generator=new THREE.PMREMGenerator(gl);
    const room=new RoomEnvironment();
    const target=generator.fromScene(room,.04);
    scene.environment=target.texture;scene.environmentIntensity=.35;
    generator.dispose();room.dispose();invalidate();
    return()=>{scene.environment=null;target.dispose();};
  },[gl,scene,invalidate]);
  useEffect(()=>{const fail=(e:Event)=>{e.preventDefault();onFailure();};gl.domElement.addEventListener('webglcontextlost',fail);return()=>gl.domElement.removeEventListener('webglcontextlost',fail);},[gl,onFailure]);
  return null;
}

function SceneLighting({tier}:{tier:WorldTier}){
  const key=useRef<THREE.DirectionalLight>(null);
  const {pointer}=useThree();
  useFrame(()=>{if(key.current){key.current.position.x=3+pointer.x*.3;key.current.position.y=7+pointer.y*.2;}});
  return <><ambientLight intensity={.48} color="#7d94a6" /><hemisphereLight args={['#628099','#03070c',.55]} /><directionalLight ref={key} position={[3,7,8]} intensity={2.9} color="#c3d9e4" castShadow={tier==='desktop'} shadow-mapSize={[1024,1024]} shadow-bias={-.001} shadow-camera-left={-18} shadow-camera-right={18} shadow-camera-top={14} shadow-camera-bottom={-14} /><directionalLight position={[-7,4,-2]} intensity={2} color="#426d92" />{tier!=='mobile'&&<spotLight position={[8,8,12]} angle={.65} penumbra={1} intensity={160} color="#76a8c2" distance={50} decay={1.8} />}<pointLight position={[5,2,4]} intensity={4} color="#895061" distance={10} /><pointLight position={[0,0,15]} intensity={14} color="#a8bdcb" distance={30} /></>;
}

function IntelligenceWorld({layer,tier,reduced,focus,onHover,onPerformanceDrop}:Props){
  const {camera,pointer,invalidate}=useThree();
  const time=useRef(0);
  const world=useRef<THREE.Group>(null);
  const scroll=useRef(0);
  const performance=useRef({frames:0,elapsed:0,total:0});
  useEffect(()=>{performance.current={frames:0,elapsed:0,total:0};},[tier]);
  const artifacts=useMemo(()=>visibleArtifacts(tier),[tier]);
  const positions=useMemo(()=>new Map(artifacts.map(a=>[a.id,new THREE.Vector3(...a.position)])),[artifacts]);
  useEffect(()=>{
    const scroller=document.querySelector('.public-main')??document.querySelector('.app-shell main');
    const update=()=>{if(scroller)scroll.current=Math.min(1,scroller.scrollTop/Math.max(1,scroller.scrollHeight-scroller.clientHeight));};
    update();scroller?.addEventListener('scroll',update,{passive:true});
    return()=>scroller?.removeEventListener('scroll',update);
  },[layer]);
  useEffect(()=>{if(reduced){camera.position.set(0,1,tier==='mobile'?24:20);camera.lookAt(tier==='mobile'?2.5:0,0,0);invalidate();}},[camera,reduced,tier,invalidate]);
  useFrame((_,dt)=>{
    if(reduced)return;
    time.current+=Math.min(dt,.045);
    const t=time.current;
    const x=layer==='about'?-.9:layer==='intelligence'?.65:layer==='access'?1.2:0;
    camera.position.x=THREE.MathUtils.damp(camera.position.x,x+pointer.x*(tier==='mobile'?.08:.32)+Math.sin(t*.06)*.14,1.5,dt);
    camera.position.y=THREE.MathUtils.damp(camera.position.y,1+pointer.y*.16-scroll.current*.45,1.5,dt);
    camera.position.z=THREE.MathUtils.damp(camera.position.z,(tier==='mobile'?24:layer==='operations'?21:20)-scroll.current*.65,1.4,dt);
    camera.lookAt(tier==='mobile'?2.5:0,0,0);
    if(world.current)world.current.rotation.y=Math.sin(t*.035)*.018;
    const budget=performance.current;budget.total+=dt;budget.elapsed+=dt;budget.frames++;
    if(budget.elapsed>3){if(budget.total>8&&budget.frames/budget.elapsed<(tier==='desktop'?22:16))onPerformanceDrop();budget.frames=0;budget.elapsed=0;}
  });
  return <>
    <group ref={world}>{artifacts.map((a,i)=><FloatingArtifact key={a.id} artifact={a} index={i} position={positions.get(a.id)!} tier={tier} reduced={reduced} focus={focus===a.category} onHover={onHover} />)}<ThreatConnections positions={positions} reduced={reduced} /></group>
    <AtmosphericParticles tier={tier} reduced={reduced} />
    <gridHelper args={[90,tier==='desktop'?60:30,'#142b36','#0b1924']} position={[0,-6.3,-8]} />
    <mesh rotation={[-Math.PI/2,0,0]} position={[0,-6.35,0]} receiveShadow><planeGeometry args={[120,120]} /><meshStandardMaterial color="#03090f" roughness={.78} metalness={.3} /></mesh>
    <AtmosphericBeam position={[7,1,-14]} color="#247492" />
    {tier!=='mobile'&&<AtmosphericBeam position={[-9,3,-20]} color="#183d75" />}
  </>;
}

function FloatingArtifact({artifact:a,index,position,tier,reduced,focus,onHover}:{artifact:ThreatArtifact;index:number;position:THREE.Vector3;tier:WorldTier;reduced:boolean;focus:boolean;onHover:(id:string|null)=>void}){
  const root=useRef<THREE.Group>(null);
  const model=useRef<THREE.Group>(null);
  const hover=useRef(false);
  const t=useRef(index*2.2);
  const base=useMemo(()=>new THREE.Vector3(...a.position),[a]);
  const light=useRef<THREE.PointLight>(null);
  const outline=useRef<THREE.Mesh>(null);
  useEffect(()=>{
    model.current?.traverse(object=>{if(!(object instanceof THREE.Mesh))return;const materials=Array.isArray(object.material)?object.material:[object.material];materials.forEach(material=>{const original=material.userData.worldBaseOpacity??material.opacity;material.userData.worldBaseOpacity=original;material.opacity=original*a.opacity;material.transparent=material.opacity<1;material.needsUpdate=true;});});
  },[a.opacity]);
  useEffect(()=>{const p=base.clone();if(tier==='mobile'){p.x=2.5+(p.x-5)*.7;p.y*=.8;}position.copy(p);root.current?.position.copy(p);},[base,tier,position]);
  useFrame((_,dt)=>{
    if(!root.current||!model.current||reduced)return;
    t.current+=Math.min(dt,.045);
    const phase=t.current;
    const x=tier==='mobile'?2.5+(base.x-5)*.7:base.x;
    const y=tier==='mobile'?base.y*.8:base.y;
    // Weapons and narcotics are the featured subjects: they spin slowly and drift wider.
    const featured=a.category==='weapons'||a.category==='narcotics';
    const drift=featured?70:8;
    position.set(x+Math.sin(phase*.06)*a.velocity[0]*drift,y+Math.sin(phase*a.frequency)*a.amplitude*(featured?2.2:1),base.z+Math.sin(phase*.07)*(featured?.6:.18)+(hover.current?.12:0));
    root.current.position.copy(position);
    model.current.rotation.x=a.rotation[0]+Math.sin(phase*.08)*(featured?.12:.04);
    model.current.rotation.y=a.type==='crypto'?a.rotation[1]+phase*.06:featured?a.rotation[1]+phase*.16*(index%2?1:-1):a.rotation[1]+Math.sin(phase*.07)*.07;
    model.current.rotation.z=a.rotation[2]+Math.cos(phase*.06)*.025;
    root.current.scale.setScalar(THREE.MathUtils.damp(root.current.scale.x,a.scale*(hover.current?1.045:focus?1.03:1),2,dt));
    if(light.current)light.current.intensity=THREE.MathUtils.damp(light.current.intensity,hover.current?4:0,3,dt);
    if(outline.current)outline.current.visible=hover.current||focus;
  });
  return <group ref={root} position={position} scale={a.scale}>
    <group ref={model} rotation={a.rotation} onPointerOver={e=>{e.stopPropagation();hover.current=true;onHover(a.category);}} onPointerOut={()=>{hover.current=false;onHover(null);}}><ThreatObject type={a.type} accent={a.accent} /></group>
    <pointLight ref={light} color={a.accent} intensity={0} distance={3} position={[0,.4,1]} />
    <mesh ref={outline} visible={focus} rotation={[Math.PI/2,0,0]}><torusGeometry args={[.94,.006,4,48]} /><meshBasicMaterial color={a.accent} transparent opacity={.35} /></mesh>
  </group>;
}

function ThreatConnections({positions,reduced}:{positions:Map<string,THREE.Vector3>;reduced:boolean}){
  const {invalidate}=useThree();
  const path=useRef<THREE.LineSegments>(null),signal=useRef<THREE.Points>(null),clock=useRef(0);
  const pairs=useMemo(()=>[['w-01','t-01'],['t-01','c-01'],['c-01','s-01'],['s-01','m-01'],['n-01','t-01'],['s-03','i-01']].flatMap(([a,b])=>{const p=positions.get(a!),q=positions.get(b!);return p&&q?[[p,q] as const]:[];}),[positions]);
  const lines=useMemo(()=>new Float32Array(pairs.length*6),[pairs]),dots=useMemo(()=>new Float32Array(pairs.length*3),[pairs]);
  const update=(t:number)=>pairs.forEach(([a,b],i)=>{a.toArray(lines,i*6);b.toArray(lines,i*6+3);const u=(t*.06+i*.23)%1;dots[i*3]=a.x+(b.x-a.x)*u;dots[i*3+1]=a.y+(b.y-a.y)*u;dots[i*3+2]=a.z+(b.z-a.z)*u;});
  update(clock.current);
  useEffect(()=>{update(clock.current);if(path.current)path.current.geometry.attributes.position!.needsUpdate=true;if(signal.current)signal.current.geometry.attributes.position!.needsUpdate=true;invalidate();},[pairs,reduced,invalidate]);
  useFrame((_,dt)=>{if(reduced)return;clock.current+=Math.min(dt,.045);update(clock.current);if(path.current)path.current.geometry.attributes.position!.needsUpdate=true;if(signal.current)signal.current.geometry.attributes.position!.needsUpdate=true;});
  return <><lineSegments ref={path} frustumCulled={false}><bufferGeometry><bufferAttribute attach="attributes-position" args={[lines,3]} /></bufferGeometry><lineBasicMaterial color="#46798b" transparent opacity={.14} /></lineSegments><points ref={signal} frustumCulled={false}><bufferGeometry><bufferAttribute attach="attributes-position" args={[dots,3]} /></bufferGeometry><pointsMaterial color="#62adbf" size={.045} transparent opacity={.7} depthWrite={false} /></points></>;
}

function AtmosphericParticles({tier,reduced}:{tier:WorldTier;reduced:boolean}){
  const dust=useRef<THREE.Points>(null);
  const geometry=useMemo(()=>{
    const count=tier==='desktop'?160:tier==='tablet'?85:40;
    const coords=new Float32Array(count*3);
    for(let i=0;i<count;i++)coords.set([Math.sin(i*127.1)*19,Math.cos(i*311.7)*10,Math.sin(i*53.1)*15-10],i*3);
    return coords;
  },[tier]);
  useFrame((_,dt)=>{if(dust.current&&!reduced){dust.current.rotation.y+=Math.min(dt,.045)*.0015;dust.current.rotation.z+=Math.min(dt,.045)*.0005;}});
  return <points ref={dust}><bufferGeometry><bufferAttribute attach="attributes-position" args={[geometry,3]} /></bufferGeometry><pointsMaterial color="#779aaf" size={tier==='mobile'?.027:.018} transparent opacity={.3} depthWrite={false} /></points>;
}

function AtmosphericBeam({position,color}:{position:[number,number,number];color:string}){
  return <mesh position={position} rotation={[0,0,-.18]}><coneGeometry args={[3.5,19,12,1,true]} /><meshBasicMaterial color={color} transparent opacity={.024} side={THREE.DoubleSide} depthWrite={false} blending={THREE.AdditiveBlending} /></mesh>;
}

/** Existing Three.js addons provide bloom and restrained depth blur; mobile skips them. */
function AtmosphericLens({reduced}:{reduced:boolean}){
  const {gl,scene,camera,size,invalidate}=useThree();
  const lens=useRef<EffectComposer|null>(null);
  useEffect(()=>{
    const composer=new EffectComposer(gl);
    const render=new RenderPass(scene,camera);
    const depth=new BokehPass(scene,camera,{focus:22,aperture:.00006,maxblur:.004});
    const bloom=new UnrealBloomPass(new THREE.Vector2(1,1),.24,.6,.95);
    const output=new OutputPass();
    composer.addPass(render);composer.addPass(depth);composer.addPass(bloom);composer.addPass(output);
    lens.current=composer;
    const dimensions=gl.getSize(new THREE.Vector2());
    composer.setPixelRatio(Math.min(gl.getPixelRatio(),1.2));composer.setSize(dimensions.x,dimensions.y);invalidate();
    return()=>{[render,depth,bloom,output].forEach(p=>p.dispose());composer.dispose();lens.current=null;};
  },[gl,scene,camera,invalidate]);
  useEffect(()=>{lens.current?.setPixelRatio(Math.min(gl.getPixelRatio(),1.2));lens.current?.setSize(size.width,size.height);invalidate();},[gl,size,invalidate]);
  useFrame((_,dt)=>{if(lens.current)lens.current.render(reduced?0:Math.min(dt,.045));else gl.render(scene,camera);},1);
  return null;
}
