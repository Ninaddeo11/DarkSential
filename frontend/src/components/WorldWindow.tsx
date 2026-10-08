import { useWorld } from '../visuals/DarkWebEnvironment';
import { TAXONOMY } from '../visuals/model';

/** An opening onto the single global world, never another canvas or boxed model. */
export function WorldWindow({caption='UNDERGROUND OBSERVATORY',className='',controls=false}:{caption?:string;className?:string;controls?:boolean}){
  const {focus,setFocus}=useWorld();
  const selected=TAXONOMY.find(n=>n.id===focus);
  return <div className={`world-window ${className}`} role="group" aria-label="Illustrative underground threat environment"><div className="world-window-header"><span><i /> {caption}</span><span>ILLUSTRATIVE WORLD</span></div><div className="world-window-space" aria-hidden="true"><span className="world-reticle reticle-one" /><span className="world-reticle reticle-two" /></div>{controls&&<nav className="world-category-controls" aria-label="Explore threat categories">{TAXONOMY.map(n=><button key={n.id} type="button" aria-pressed={focus===n.id} onClick={()=>setFocus(focus===n.id?null:n.id)}>{n.label}</button>)}</nav>}{selected&&controls&&<div className="world-selection" aria-live="polite"><span>RESEARCH FOCUS / {selected.label.toUpperCase()}</span><p>{selected.detail}</p></div>}<div className="world-window-footer"><span>PROCEDURAL ARTIFACTS / FICTIONAL ASSOCIATIONS</span><span>MOVE TO EXPLORE ↗</span></div></div>;
}
