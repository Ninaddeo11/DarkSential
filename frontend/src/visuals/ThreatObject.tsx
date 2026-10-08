import { useMemo, type ReactNode } from 'react';
import { RoundedBox } from '@react-three/drei';
import * as THREE from 'three';
import type { ArtifactKind } from './worldModel';

type Vec=[number,number,number];
interface Surface { color:string;metalness:number;roughness:number; }
const METAL:Surface={color:'#455461',metalness:.66,roughness:.38};
const RUBBER:Surface={color:'#111b22',metalness:.1,roughness:.85};
const PACK:Surface={color:'#566269',metalness:.08,roughness:.8};
const DARK:Surface={color:'#101f2a',metalness:.65,roughness:.4};

function Block({size,position=[0,0,0],rotation=[0,0,0],surface=METAL,children}:{size:Vec;position?:Vec;rotation?:Vec;surface?:Surface;children?:ReactNode}) {
  return <RoundedBox args={size} radius={Math.min(.035,...size.map(n=>n/5))} smoothness={2} position={position} rotation={rotation} castShadow receiveShadow><meshStandardMaterial {...surface} />{children}</RoundedBox>;
}
function Strip({size,position=[0,0,0],color}:{size:Vec;position?:Vec;color:string}){
  return <mesh position={position}><boxGeometry args={size} /><meshStandardMaterial color={color} emissive={color} emissiveIntensity={.35} roughness={.45} metalness={.5} /></mesh>;
}

export function FloatingWeapon({rifle=false,accent}:{rifle?:boolean;accent:string}) {
  const shape=useMemo(()=>{
    const s=new THREE.Shape();
    const coords=rifle?[[-1.7,.12],[-1.1,.32],[-.9,.12],[.8,.12],[.8,-.12],[.14,-.12],[.02,-.55],[-.25,-.5],[-.3,-.13],[-.57,-.13],[-.68,-.58],[-.92,-.58],[-.85,-.1],[-1.7,-.1]]:[[-.78,.3],[.78,.3],[.8,.09],[.14,.09],[-.07,-.05],[-.28,-.62],[-.66,-.57],[-.5,-.01],[-.78,.01]];
    coords.forEach(([x,y],i)=>i?s.lineTo(x!,y!):s.moveTo(x!,y!));s.closePath();return s;
  },[rifle]);
  return <group>
    <mesh castShadow receiveShadow><extrudeGeometry args={[shape,{depth:.2,bevelEnabled:true,bevelSegments:2,steps:1,bevelSize:.024,bevelThickness:.022}]} /><meshStandardMaterial {...METAL} /></mesh>
    {!rifle&&<><Block size={[1.47,.17,.24]} position={[0,.24,.1]} /><Block size={[.78,.07,.2]} position={[.35,.04,.1]} surface={DARK} /><mesh position={[.805,.19,.1]} rotation={[0,Math.PI/2,0]}><cylinderGeometry args={[.053,.053,.018,12]} /><meshStandardMaterial {...RUBBER} /></mesh><Block size={[.05,.04,.045]} position={[.6,.345,.1]} surface={DARK} /></>}
    <Block size={rifle?[.2,.36,.23]:[.25,.4,.23]} position={rifle?[-.8,-.32,.1]:[-.44,-.31,.1]} rotation={[0,0,rifle?0:-.27]} surface={RUBBER} />
    <Strip size={[rifle?1.25:1.3,.012,.012]} position={[rifle?-.2:0,.29,.23]} color={accent} />
    <mesh position={[rifle?-.18:-.16,-.1,.1]} rotation={[0,0,.2]}><torusGeometry args={[.14,.018,6,16,Math.PI*1.4]} /><meshStandardMaterial {...METAL} /></mesh>
    {rifle&&<><Block size={[.8,.16,.18]} position={[1.15,.01,.1]} /><Block size={[.17,.3,.16]} position={[.85,.15,.1]} /></>}
    {[0,1,2,3].map(i=><Block key={i} size={[.025,.13,.012]} position={[-.55+i*.07,.15,.224]} surface={RUBBER} />)}
  </group>;
}

export function NarcoticsPackage({accent}:{accent:string}) {
  return <group>
    <Block size={[1.25,.75,.85]} surface={PACK} />
    <Block size={[1.29,.09,.88]} position={[0,.04,0]} surface={RUBBER} />
    <Block size={[.12,.78,.89]} position={[-.27,0,0]} surface={RUBBER} />
    <Block size={[.35,.25,.018]} position={[.26,.15,.44]} surface={{color:'#7f8b8d',roughness:.95,metalness:0}} />
    <Strip size={[.23,.012,.02]} position={[.26,.19,.455]} color={accent} />
    {[0,1,2,3,4].map(i=><Block key={i} size={[.012,.1,.012]} position={[.16+i*.04,.09,.46]} surface={DARK} />)}
  </group>;
}

export function TraffickingCargo({accent}:{accent:string}) {
  return <group>
    <Block size={[2,1.05,.95]} surface={{color:'#343e44',metalness:.5,roughness:.75}} />
    {Array.from({length:12},(_,i)=><Block key={i} size={[.055,.93,.025]} position={[-.88+i*.16,0,.49]} surface={METAL} />)}
    {[-1.015,1.015].map(x=><group key={x}><Block size={[.02,1,.9]} position={[x,0,0]} surface={DARK} />{[-.22,.22].map(z=><Block key={z} size={[.03,.87,.018]} position={[x,z*.04,z]} />)}</group>)}
    <Strip size={[1.9,.015,.015]} position={[0,.52,.49]} color={accent} />
    <Block size={[.3,.2,.025]} position={[.55,-.25,.51]} surface={PACK} />
  </group>;
}

export function ServerObject({accent}:{accent:string}) {
  return <group>
    <Block size={[.86,2.4,.65]} surface={DARK} />
    {Array.from({length:7},(_,i)=><group key={i} position={[0,.96-i*.31,.34]}><Block size={[.75,.25,.028]} surface={METAL} /><Strip size={[.036,.026,.018]} position={[-.28,.02,.02]} color={accent} />{[0,1,2,3].map(j=><Block key={j} size={[.075,.017,.018]} position={[-.05+j*.13,.02,.02]} surface={RUBBER} />)}</group>)}
    <Strip size={[.014,2.2,.014]} position={[.42,0,.33]} color={accent} />
  </group>;
}

export function CryptoArtifact({accent}:{accent:string}) {
  return <group rotation={[Math.PI/2,0,0]}>
    <mesh castShadow><cylinderGeometry args={[.58,.58,.12,32]} /><meshStandardMaterial color="#5a584c" metalness={.88} roughness={.28} /></mesh>
    {[.066,-.066].map(y=><group key={y} position={[0,y,0]} rotation={[Math.PI/2,0,0]}><mesh><torusGeometry args={[.49,.018,6,32]} /><meshStandardMaterial color={accent} metalness={.7} roughness={.3} /></mesh><mesh><torusGeometry args={[.34,.022,6,6]} /><meshStandardMaterial color={accent} metalness={.85} roughness={.25} /></mesh><Block size={[.027,.55,.018]} position={[0,0,.02]} surface={{color:accent,metalness:.85,roughness:.25}} /></group>)}
    {Array.from({length:24},(_,i)=><Block key={i} size={[.023,.025,.08]} position={[Math.cos(i*Math.PI/12)*.585,0,Math.sin(i*Math.PI/12)*.585]} />)}
  </group>;
}

function Phone({accent}:{accent:string}){
  return <group><Block size={[.57,1.15,.13]} surface={RUBBER} /><Block size={[.47,.73,.01]} position={[0,.08,.071]} surface={DARK} /><Strip size={[.32,.014,.014]} position={[0,.26,.085]} color={accent} />{Array.from({length:9},(_,i)=><Block key={i} size={[.09,.03,.014]} position={[-.15+(i%3)*.15,-.36-Math.floor(i/3)*.055,.071]} />)}<mesh position={[0,-.21,.08]}><circleGeometry args={[.027,12]} /><meshStandardMaterial color={accent} emissive={accent} emissiveIntensity={.35} /></mesh></group>;
}
function Terminal({accent}:{accent:string}){
  return <group><group rotation={[-.18,0,0]}><Block size={[1.65,1.05,.09]} surface={METAL} /><Block size={[1.49,.87,.014]} position={[0,0,.057]} surface={DARK} />{Array.from({length:6},(_,i)=><Strip key={i} size={[.55+i%3*.2,.013,.012]} position={[-.25,.3-i*.095,.069]} color={accent} />)}</group><Block size={[1.65,.06,1]} position={[0,-.59,.48]} rotation={[.12,0,0]} surface={METAL} /></group>;
}
function EvidenceCase({accent}:{accent:string}){
  return <group><Block size={[1.35,.65,.88]} surface={RUBBER} /><Block size={[1.38,.08,.9]} position={[0,.2,0]} />{[-.42,.42].map(x=><Block key={x} size={[.09,.19,.04]} position={[x,.19,.46]} />)}<Strip size={[.4,.012,.018]} position={[0,.11,.45]} color={accent} /><mesh position={[0,.37,0]} rotation={[0,0,0]}><torusGeometry args={[.18,.035,5,12,Math.PI]} /><meshStandardMaterial {...METAL} /></mesh></group>;
}
function Capsules({accent}:{accent:string}){
  return <group><mesh castShadow><cylinderGeometry args={[.27,.28,.9,16]} /><meshPhysicalMaterial color="#7290a0" metalness={.05} roughness={.25} transparent opacity={.28} depthWrite={false} /></mesh>{[-.47,.47].map(y=><mesh key={y} position={[0,y,0]}><cylinderGeometry args={[.29,.29,.06,16]} /><meshStandardMaterial {...METAL} /></mesh>)}{[0,1,2].map(i=><mesh key={i} position={[(i-1)*.11,-.12+i*.07,.02]} rotation={[.3,.2,i*.5]}><capsuleGeometry args={[.07,.2,4,8]} /><meshStandardMaterial color={i%2?accent:'#929d9f'} roughness={.75} /></mesh>)}</group>;
}
function Vehicle({accent}:{accent:string}){
  return <group><Block size={[1.6,.48,.7]} surface={DARK} /><Block size={[.75,.5,.67]} position={[-.4,.4,0]} surface={METAL} /><Block size={[.015,.2,.5]} position={[-.785,.44,0]} surface={RUBBER} />{[-.57,.57].flatMap(x=>[-.36,.36].map(z=><mesh key={`${x}${z}`} position={[x,-.28,z]} rotation={[Math.PI/2,0,0]}><cylinderGeometry args={[.18,.18,.08,12]} /><meshStandardMaterial {...RUBBER} /></mesh>))}<Strip size={[.012,.04,.44]} position={[.808,.03,0]} color={accent} /></group>;
}
function Identity({accent}:{accent:string}){
  return <group rotation={[0,0,.1]}><Block size={[1.2,.75,.04]} surface={METAL} /><mesh position={[-.3,.1,.028]}><circleGeometry args={[.13,16]} /><meshStandardMaterial color="#607482" roughness={.7} /></mesh><Block size={[.32,.15,.012]} position={[-.3,-.13,.03]} />{[0,1,2].map(i=><Strip key={i} size={[.38-i*.05,.014,.014]} position={[.2,.15-i*.12,.032]} color={accent} />)}{[0,1,2,3].map(i=><Block key={i} size={[.08,.09,.04]} position={[.55+i*.1,-.35-i*.04,.06+i*.04]} />)}</group>;
}
function CyberArtifact({accent,fragment=false}:{accent:string;fragment?:boolean}){
  return <group><mesh castShadow><icosahedronGeometry args={[.43,0]} /><meshStandardMaterial color="#212b35" metalness={.8} roughness={.25} emissive={accent} emissiveIntensity={.1} /></mesh>{Array.from({length:fragment?5:8},(_,i)=><Block key={i} size={[.17,.18,.2]} position={[Math.sin(i*2.4)*.66,Math.cos(i*1.6)*.61,Math.sin(i)*.35]} rotation={[i*.2,i*.6,.2]} surface={{color:'#2c3c49',metalness:.7,roughness:.35}} />)}{!fragment&&<mesh rotation={[.4,.3,.2]}><torusGeometry args={[.72,.01,6,48]} /><meshStandardMaterial color={accent} emissive={accent} emissiveIntensity={1.1} /></mesh>}</group>;
}

/** Reusable solid forensic models; every asset is generated by the bundler. */
export function ThreatObject({type,accent}:{type:ArtifactKind;accent:string}){
  switch(type){
    case 'handgun': return <FloatingWeapon accent={accent} />;
    case 'rifle': return <FloatingWeapon accent={accent} rifle />;
    case 'case': return <EvidenceCase accent={accent} />;
    case 'package': return <NarcoticsPackage accent={accent} />;
    case 'capsules': return <Capsules accent={accent} />;
    case 'cargo': return <TraffickingCargo accent={accent} />;
    case 'server': return <ServerObject accent={accent} />;
    case 'phone': return <Phone accent={accent} />;
    case 'terminal': return <Terminal accent={accent} />;
    case 'crypto': return <CryptoArtifact accent={accent} />;
    case 'vehicle': return <Vehicle accent={accent} />;
    case 'identity': return <Identity accent={accent} />;
    case 'malware': return <CyberArtifact accent={accent} />;
    case 'fragment': return <CyberArtifact accent={accent} fragment />;
  }
}
