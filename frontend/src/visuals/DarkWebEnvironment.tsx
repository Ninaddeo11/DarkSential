import { Component, createContext, lazy, Suspense, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { useLocation } from 'react-router';
import { supportsWebGL } from './NexusScene';
import { worldLayer, type WorldLayer } from './worldModel';

const Engine=lazy(()=>import('./DarkWebWorldEngine').then(m=>({default:m.DarkWebWorldEngine})));
export type WorldTier='mobile'|'tablet'|'desktop';
interface WorldValue {focus:string|null;setFocus:(id:string|null)=>void;hovered:string|null;setHovered:(id:string|null)=>void;}
const WorldContext=createContext<WorldValue|null>(null);
export function WorldProvider({children}:{children:ReactNode}){
  const [focus,setFocus]=useState<string|null>(null);
  const [hovered,setHovered]=useState<string|null>(null);
  return <WorldContext.Provider value={{focus,setFocus,hovered,setHovered}}>{children}</WorldContext.Provider>;
}
export function useWorld(){const value=useContext(WorldContext);if(!value)throw new Error('World context is missing');return value;}

/** This component and its Canvas remain mounted above every route. */
export function DarkWebEnvironment(){
  const {pathname,search}=useLocation();
  const {focus,setFocus,hovered,setHovered}=useWorld();
  const [mounted,setMounted]=useState(false);
  const [reduced,setReduced]=useState(true);
  const [hidden,setHidden]=useState(false);
  const [tier,setTier]=useState<WorldTier>('mobile');
  const [fallback,setFallback]=useState(false);
  const [limited,setLimited]=useState(0);
  const reduceQuality=useCallback(()=>setLimited(level=>Math.min(2,level+1)),[]);
  const host=useRef<HTMLDivElement>(null);
  const layer=worldLayer(pathname);
  useEffect(()=>{
    const media=window.matchMedia('(prefers-reduced-motion: reduce)');
    const motion=()=>setReduced(media.matches);
    const visibility=()=>setHidden(document.hidden);
    const resize=()=>setTier(window.innerWidth<768?'mobile':window.innerWidth<1200?'tablet':'desktop');
    const device=navigator as Navigator&{deviceMemory?:number;connection?:{saveData?:boolean}};
    setFallback(!supportsWebGL()||(device.deviceMemory??8)<=2||navigator.hardwareConcurrency<=2||!!device.connection?.saveData);
    motion();visibility();resize();setMounted(true);
    window.addEventListener('resize',resize);document.addEventListener('visibilitychange',visibility);media.addEventListener('change',motion);
    return ()=>{window.removeEventListener('resize',resize);document.removeEventListener('visibilitychange',visibility);media.removeEventListener('change',motion);};
  },[]);
  useEffect(()=>{setHovered(null);const category=new URLSearchParams(search).get('category');setFocus(category==='vulnerabilities'?'exploits':category);},[pathname,search,setFocus,setHovered]);
  const effectiveTier=limited>0&&tier==='desktop'?'tablet':tier;
  const staticWorld=<AtmosphericFallback paused={hidden} reduced={reduced} />;
  return <div ref={host} className={`dark-web-environment world-${layer} ${hidden?'world-paused':''}`} data-world-layer={layer} data-world-tier={effectiveTier} data-world-mode={fallback?'atmospheric':'3d'} data-world-motion={reduced?'reduced':limited===2?'adaptive-static':'animated'} aria-hidden="true">
    {mounted&&!fallback?<WorldBoundary fallback={staticWorld}><Suspense fallback={staticWorld}><Engine layer={layer} tier={effectiveTier} reduced={reduced||limited===2} paused={hidden} focus={focus} eventSource={document.getElementById('nexus-app')!} onHover={setHovered} onFailure={()=>{setFallback(true);setHovered(null);}} onPerformanceDrop={reduceQuality} /></Suspense></WorldBoundary>:staticWorld}
    <div className="world-vignette" />
    <div className="world-grain" />
    {hovered&&<div className="world-artifact-tooltip"><span>FORENSIC ARTIFACT / ILLUSTRATIVE</span><strong>{hovered.replace(/-/g,' ').toUpperCase()}</strong><small>FICTIONAL EVIDENCE / RESEARCH SCOPE</small></div>}
    {mounted&&fallback&&<span className="world-static-indicator">ATMOSPHERIC INTELLIGENCE MODE</span>}
  </div>;
}

class WorldBoundary extends Component<{children:ReactNode;fallback:ReactNode},{failed:boolean}>{
  state={failed:false};
  static getDerivedStateFromError(){return{failed:true};}
  render(){return this.state.failed?this.props.fallback:this.props.children;}
}
function AtmosphericFallback({paused,reduced}:{paused:boolean;reduced:boolean}){
  return <div className={`world-fallback ${paused||reduced?'is-still':''}`}><div className="fallback-haze" /><svg className="fallback-infrastructure" viewBox="0 0 1200 800"><g fill="#102534" stroke="#367488" strokeWidth="1"><path d="M870 180l130 35v310l-130-35zM890 225l90 25M890 275l90 25M890 325l90 25M890 375l90 25M890 425l90 25"/><path d="M610 430l160-25 100 70-160 35zM610 430v90l100 80 160-40v-85M710 510v90"/><path d="M460 225l85-20 5 100-85 20zM477 241l51-12M479 260l51-12"/></g><g fill="none" stroke="#175064" opacity=".5"><path d="M470 275Q740 100 945 345M945 345Q910 660 710 505M710 505Q590 330 470 275"/></g></svg>{Array.from({length:22},(_,i)=><i key={i} className="fallback-particle" style={{left:`${(i*43)%100}%`,top:`${(i*67)%100}%`,animationDelay:`-${i*1.7}s`}} />)}</div>;
}

export const WORLD_LAYER_COPY:Record<WorldLayer,string>={landing:'UNDERGROUND OBSERVATORY',intelligence:'FORENSIC RESEARCH LAYER',about:'MISSION / CONTEXT / EVIDENCE',access:'NEXUS ACCESS CONTROL',operations:'OPERATIONAL INTELLIGENCE LAYER'};
