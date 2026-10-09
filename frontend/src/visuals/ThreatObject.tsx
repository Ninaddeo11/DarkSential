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

const GUNMETAL:Surface={color:'#2b3238',metalness:.82,roughness:.32};
const STEEL:Surface={color:'#5b6670',metalness:.9,roughness:.25};
const WOOD:Surface={color:'#6b4528',metalness:.05,roughness:.62};
const POLYMER:Surface={color:'#1a1f24',metalness:.15,roughness:.7};

function Tube({r,len,position,rotation=[0,0,Math.PI/2],surface=STEEL}:{r:number;len:number;position:Vec;rotation?:Vec;surface?:Surface}){
  return <mesh position={position} rotation={rotation} castShadow><cylinderGeometry args={[r,r,len,16]} /><meshStandardMaterial {...surface} /></mesh>;
}

/** Semi-automatic pistol, muzzle toward +x. */
function Pistol({accent}:{accent:string}){
  return <group>
    {/* slide with rear serrations, sights and ejection port */}
    <Block size={[1.5,.24,.21]} position={[.05,.24,0]} surface={GUNMETAL} />
    {Array.from({length:7},(_,i)=><Block key={i} size={[.018,.2,.215]} position={[-.62+i*.045,.24,0]} surface={POLYMER} />)}
    <Block size={[.32,.05,.215]} position={[.2,.33,0]} surface={POLYMER} />
    <Block size={[.05,.06,.06]} position={[.72,.38,0]} surface={GUNMETAL} />
    <Block size={[.08,.06,.12]} position={[-.62,.38,0]} surface={GUNMETAL} />
    <Tube r={.048} len={.08} position={[.8,.2,0]} surface={POLYMER} />
    {/* frame, accessory rail, trigger guard and trigger */}
    <Block size={[1.12,.15,.19]} position={[.18,.05,0]} surface={POLYMER} />
    {[0,1,2].map(i=><Block key={i} size={[.06,.03,.2]} position={[.38+i*.1,-.04,0]} surface={POLYMER} />)}
    <mesh position={[-.06,-.1,0]} rotation={[0,0,Math.PI]}><torusGeometry args={[.15,.026,8,20,Math.PI]} /><meshStandardMaterial {...POLYMER} /></mesh>
    <Block size={[.04,.14,.05]} position={[-.08,-.06,0]} rotation={[0,0,.25]} surface={STEEL} />
    {/* angled grip with texture panels and magazine base plate */}
    <group position={[-.5,-.33,0]} rotation={[0,0,-.26]}>
      <Block size={[.34,.66,.2]} surface={POLYMER} />
      {Array.from({length:6},(_,i)=><Block key={i} size={[.24,.022,.205]} position={[0,.22-i*.09,0]} surface={RUBBER} />)}
      <Block size={[.38,.06,.22]} position={[0,-.35,0]} surface={GUNMETAL} />
    </group>
    <Block size={[.08,.07,.12]} position={[-.72,.3,0]} surface={GUNMETAL} />
    <Strip size={[1.1,.01,.01]} position={[.1,.37,.11]} color={accent} />
  </group>;
}

/** AK-pattern assault rifle, muzzle toward +x. */
function Rifle({accent}:{accent:string}){
  const stock=useMemo(()=>{
    const s=new THREE.Shape();
    [[0,.1],[-1.05,.02],[-1.1,-.36],[-.95,-.38],[0,-.12]].forEach(([x,y],i)=>i?s.lineTo(x!,y!):s.moveTo(x!,y!));
    s.closePath();return s;
  },[]);
  return <group>
    {/* receiver, dust cover, rear sight */}
    <Block size={[1.15,.26,.17]} position={[0,0,0]} surface={GUNMETAL} />
    <Block size={[1.0,.08,.16]} position={[-.05,.16,0]} surface={STEEL} />
    <Block size={[.16,.07,.12]} position={[.45,.21,0]} surface={GUNMETAL} />
    {/* wooden handguard, gas tube, barrel, front sight and muzzle brake */}
    <Block size={[.62,.18,.18]} position={[.88,.0,0]} surface={WOOD} />
    <Block size={[.5,.09,.15]} position={[.86,.14,0]} surface={WOOD} />
    <Tube r={.033} len={.75} position={[1.05,.2,0]} surface={GUNMETAL} />
    <Tube r={.032} len={1.05} position={[1.55,.06,0]} />
    <Block size={[.05,.16,.05]} position={[1.72,.16,0]} surface={GUNMETAL} />
    <Tube r={.046} len={.16} position={[2.1,.06,0]} surface={GUNMETAL} />
    {/* curved 30-round magazine */}
    {Array.from({length:6},(_,i)=><Block key={i} size={[.2,.14,.13]} position={[.22+i*.045+i*i*.006,-.2-i*.12,0]} rotation={[0,0,.12+i*.07]} surface={GUNMETAL} />)}
    {/* trigger guard, pistol grip and wooden stock */}
    <mesh position={[-.12,-.17,0]} rotation={[0,0,Math.PI]}><torusGeometry args={[.13,.022,8,20,Math.PI]} /><meshStandardMaterial {...STEEL} /></mesh>
    <group position={[-.38,-.3,0]} rotation={[0,0,-.38]}><Block size={[.16,.4,.15]} surface={WOOD} /></group>
    <mesh position={[-.55,0,-.075]} castShadow><extrudeGeometry args={[stock,{depth:.15,bevelEnabled:true,bevelSegments:2,steps:1,bevelSize:.02,bevelThickness:.02}]} /><meshStandardMaterial {...WOOD} /></mesh>
    <Block size={[.05,.48,.17]} position={[-1.65,-.15,0]} surface={RUBBER} />
    <Strip size={[.9,.01,.01]} position={[-.05,.21,.09]} color={accent} />
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

/** Stack of taped narcotics bricks with stamped logos. */
function Bricks({accent}:{accent:string}){
  const tape:Surface={color:'#9a7a4a',metalness:.15,roughness:.45};
  const bricks:Vec[]=[[-.48,-.17,0],[.48,-.17,0],[0,.17,0],[-.48,-.17,-.58],[.48,-.17,-.58]];
  return <group>
    {bricks.map((p,i)=><group key={i} position={p}>
      <Block size={[.9,.32,.55]} surface={tape} />
      {[-.28,0,.28].map(x=><Block key={x} size={[.03,.33,.56]} position={[x,0,0]} surface={{color:'#7d6138',metalness:.15,roughness:.5}} />)}
      <mesh position={[.12,.165,.05]} rotation={[-Math.PI/2,0,0]}><circleGeometry args={[.09,20]} /><meshStandardMaterial color={accent} emissive={accent} emissiveIntensity={.25} roughness={.6} /></mesh>
      <mesh position={[.12,.166,.05]} rotation={[-Math.PI/2,0,0]}><ringGeometry args={[.1,.115,20]} /><meshStandardMaterial color="#2a1d10" roughness={.8} /></mesh>
    </group>)}
  </group>;
}

/** Zip baggie of white powder. */
function Baggie({accent}:{accent:string}){
  return <group>
    <mesh castShadow><boxGeometry args={[.8,1.0,.08]} /><meshPhysicalMaterial color="#cfe0e8" metalness={0} roughness={.15} transparent opacity={.32} depthWrite={false} /></mesh>
    <mesh position={[0,-.13,0]} scale={[.33,.3,.07]}><sphereGeometry args={[1,20,14]} /><meshStandardMaterial color="#eef1f2" roughness={.95} /></mesh>
    <mesh position={[-.12,-.3,.01]} scale={[.22,.12,.05]}><sphereGeometry args={[1,16,10]} /><meshStandardMaterial color="#e6eaeb" roughness={.95} /></mesh>
    <Block size={[.8,.05,.1]} position={[0,.4,0]} surface={{color:'#b23a48',metalness:.1,roughness:.5}} />
    <Strip size={[.78,.012,.012]} position={[0,.34,.05]} color={accent} />
  </group>;
}

/** Scattered tablets and two-tone capsules. */
function Pills({accent}:{accent:string}){
  const colors=['#e8e3d6',accent,'#d9a3b8','#9fd4c8','#f2d27a'];
  return <group>
    {Array.from({length:9},(_,i)=>{
      const a=i*2.39,r=.18+(i%3)*.22;
      return <mesh key={i} position={[Math.cos(a)*r,Math.sin(a)*r*.6,(i%2)*.06]} rotation={[Math.PI/2+.3*(i%3),0,a]} castShadow>
        <cylinderGeometry args={[.11,.11,.05,20]} /><meshStandardMaterial color={colors[i%colors.length]} roughness={.55} />
      </mesh>;
    })}
    {Array.from({length:5},(_,i)=>{
      const a=i*1.3+.6,r=.42+(i%2)*.15;
      return <group key={i} position={[Math.cos(a)*r,Math.sin(a)*r*.6,.08]} rotation={[0,0,a+.8]}>
        <mesh position={[0,.07,0]}><capsuleGeometry args={[.055,.12,4,10]} /><meshStandardMaterial color={i%2?'#c0392b':'#2e86c1'} roughness={.35} /></mesh>
        <mesh position={[0,-.07,0]}><capsuleGeometry args={[.055,.12,4,10]} /><meshStandardMaterial color="#f4f1ea" roughness={.35} /></mesh>
      </group>;
    })}
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
    case 'handgun': return <Pistol accent={accent} />;
    case 'rifle': return <Rifle accent={accent} />;
    case 'bricks': return <Bricks accent={accent} />;
    case 'baggie': return <Baggie accent={accent} />;
    case 'pills': return <Pills accent={accent} />;
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
