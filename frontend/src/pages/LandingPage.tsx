import { Link } from 'react-router';
import { motion, useReducedMotion } from 'framer-motion';
import { NexusEntry } from '../components/NexusEntry';
import { WorldWindow } from '../components/WorldWindow';
import { useIntelligenceMetadata } from '../hooks/useIntelligenceMetadata';
import { useLive } from '../live/LiveContext';
import { useWorld } from '../visuals/DarkWebEnvironment';
import { PIPELINE, TAXONOMY } from '../visuals/model';

export function LandingPage(){
  const {counts,feeds,error}=useIntelligenceMetadata();
  const {state,authNeeded,health,me,error:liveError}=useLive();
  const {focus,setFocus}=useWorld();
  const reduced=useReducedMotion();
  const dark=feeds?.feeds.find(f=>f.name==='darkweb');
  const metrics=[
    {label:'Elevated-risk assets',value:authNeeded||!me||liveError||health?.deployment!=='lab'?null:Object.values(state.nodes).filter(n=>n.level&&['critical','high','medium'].includes(n.level)).length},
    {label:'Dark-web feed objects',value:dark?.last_run?.objects??null},
    {label:'Malware graph objects',value:counts?.Malware??null},
    {label:'Identity graph objects',value:counts?.Identity??null},
    {label:'Intrusion-set objects',value:counts?.IntrusionSet??null},
  ];
  return <div className="landing-page continuous-landing">
    <section className="public-hero cinematic-hero">
      <div className="hero-editorial"><p className="section-eyebrow system-status"><span className={health?'status-dot':'status-dot status-illustrative'} />{health?'INTELLIGENCE SYSTEM ONLINE':'INTELLIGENCE EXPERIENCE / ILLUSTRATIVE'}</p><p className="hero-classification">THE SIGNAL BELOW THE SURFACE</p>
        <h1>DARKNET<span>SENTINEL</span><em>NEXUS<span className="hero-mark">.</span></em></h1><h2>Intelligence for the<br />invisible network.</h2><p className="public-lede">Every threat leaves a trace.<br />Connect the fragments. Reveal the infrastructure.<br />Turn intelligence into defensible action.</p><div className="hero-ctas"><NexusEntry /><Link className="public-text-link" to="/intelligence">Explore intelligence ↗</Link></div><div className="hero-footnote"><span className="signal-line" />COLLECT / CORRELATE / ANALYZE / RESPOND</div>
      </div>
      <WorldWindow caption="NEXUS / UNDERGROUND OBSERVATORY" controls className="hero-world-window" />
      <a className="hero-scroll" href="#threat-ecosystem"><span>SCROLL TO INVESTIGATE</span><span aria-hidden="true">↓</span></a>
    </section>
    <div className="public-band"><span>INTELLIGENCE WITHOUT BOUNDARIES</span><span>PROVENANCE</span><span>CORRELATION</span><span>EXPLAINABLE RISK</span><span>VERIFIABLE RESPONSE</span></div>
    <section className="public-section threat-ecosystem" id="threat-ecosystem"><div className="public-section-heading"><div><p className="section-eyebrow">01 / SUBJECTS OF INVESTIGATION</p><h2>One underground.<br /><span>Many connected threats.</span></h2></div><p>Follow a research subject through the environment.<br />Enter its workspace to examine measured evidence.</p></div>
      <div className="research-index">{TAXONOMY.map((n,i)=><motion.article key={n.id} className={`research-entry ${focus===n.id?'is-focused':''}`} initial={false} whileHover={reduced?{}:{x:3}} onMouseEnter={()=>setFocus(n.id)} onFocus={()=>setFocus(n.id)}><span className="research-number">{String(i+1).padStart(2,'0')}</span><Link to={`/intelligence?category=${n.id==='exploits'?'vulnerabilities':n.id}`}><h3>{n.label}</h3><p>{n.detail}</p></Link><span className="research-open" aria-hidden="true">↗</span></motion.article>)}</div>
      <p className="data-provenance">The world is a fictional research visualization. Visual associations do not imply attribution or measured coverage.</p>
    </section>
    <section className="public-section continuous-mapping"><div className="mapping-editorial"><p className="section-eyebrow">02 / RELATIONSHIP INTELLIGENCE</p><h2>Mapping<br />the invisible<span className="hero-mark">.</span></h2><p>Behind the artifact is an association.<br />Behind the association, an infrastructure.</p><p className="public-muted">Follow abstract links between actors, cargo activity, financial infrastructure and digital traces. Source provenance and corroboration separate a signal from a finding.</p><Link className="public-text-link" to="/intelligence?category=trafficking">Investigate the research model ↗</Link></div><WorldWindow caption="ASSOCIATION FIELD / NO REAL GEOGRAPHY" /></section>
    <section className="public-section intelligence-boundaries continuous-terrain"><div><p className="section-eyebrow">03 / THE SIGNAL BENEATH THE SURFACE</p><h2>Beyond the surface<span className="hero-mark">.</span></h2><p>Forums. Actors. Infrastructure. The evidence they leave behind. The Nexus connects source intelligence with vulnerability context and observed IoT behavior.</p><p className="public-muted">Operational coverage depends on the feeds and sensors configured in your deployment.</p><Link to="/dark-web" className="public-text-link">Open dark-web intelligence ↗</Link></div><WorldWindow caption="HIDDEN INFRASTRUCTURE / RESEARCH LAYER" /></section>
    <section className="public-section live-intelligence-section"><div className="public-section-heading"><div><p className="section-eyebrow">04 / DEPLOYMENT INTELLIGENCE</p><h2>Evidence in the Nexus<span className="hero-mark">.</span></h2></div><span className="technical-badge">{health?.deployment?.toUpperCase()??'STATUS UNAVAILABLE'} / {dark?.mode?.toUpperCase()??'SOURCE UNAVAILABLE'}</span></div><div className="public-live-metrics">{metrics.map(m=><div key={m.label}><span>{m.label}</span><motion.strong key={m.value??'unavailable'} initial={reduced?false:{opacity:.4,y:4}} animate={{opacity:1,y:0}} transition={{duration:.25}}>{m.value==null?'—':String(m.value).padStart(2,'0')}</motion.strong></div>)}</div><p className="data-provenance">{error?'Some intelligence is unavailable. Enter the authenticated workspace to review source and access status.':'Counts describe the configured deployment, including fixtures when feeds use mock mode. Identity objects do not measure compromised people.'}</p></section>
    <section className="public-section workflow-section"><div className="public-section-heading"><div><p className="section-eyebrow">05 / FROM SIGNAL TO ACTION</p><h2>Every decision. Defensible.</h2></div><p>Every action begins with evidence.<br />Every decision leaves an audit trail.</p></div><ol className="intelligence-workflow">{PIPELINE.map((step,i)=><li key={step.id}><span>{String(i+1).padStart(2,'0')}</span><strong>{step.label}</strong><i aria-hidden="true">→</i></li>)}</ol></section>
    <section className="public-section cinematic-final continuous-final"><div className="final-editorial"><p className="section-eyebrow">THE ADVANTAGE IS VISIBILITY</p><h2>See what others can't<span className="hero-mark">.</span></h2><p>Correlate signals. Map threats.<br />Understand the invisible network.</p><NexusEntry /></div></section>
  </div>;
}
