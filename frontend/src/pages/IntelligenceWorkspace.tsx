import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api } from "../api/client";
import type { RelatedThreat } from "../api/types";
import { FeedHealth } from "../components/FeedHealth";
import { SimInvestigation } from "../components/SimInvestigation";
import { isHostedMode } from "../api/client";
import { scenarioFor } from "../sim/generate";
import { SIM_IOC, type Scenario } from "../sim/scenario";
import { PageHeader } from "../layout/Shell";
import { useIntelligenceMetadata } from "../hooks/useIntelligenceMetadata";
import { useLive } from "../live/LiveContext";
import { NexusScene } from "../visuals/NexusScene";
import { graphFromPaths, type IntelligenceNode } from "../visuals/model";

type Workspace = 'actors' | 'malware' | 'dark-web';
const CONFIG={
  actors:{title:'Threat actors',eyebrow:'ADVERSARY / RELATIONSHIP INTELLIGENCE',description:'Trace actor and intrusion-set associations through indicators, campaigns and infrastructure.',labels:['ThreatActor','IntrusionSet'],countKeys:['ThreatActor','IntrusionSet'],schema:['Actor','Alias','Campaign','Malware','Infrastructure','Target']},
  malware:{title:'Malware intelligence',eyebrow:'SPECIMEN / INFRASTRUCTURE INTELLIGENCE',description:'Connect malware objects to indicators, command infrastructure and observed evidence paths.',labels:['Malware'],countKeys:['Malware'],schema:['Family','Hash','Campaign','IOC','C2','Techniques']},
  'dark-web':{title:'Dark web intelligence',eyebrow:'UNDERGROUND / SOURCE INTELLIGENCE',description:'Examine configured source health and trace underground mentions through correlated indicators.',labels:[],countKeys:['Report','Identity','Indicator'],schema:['Forum','Marketplace','Actor','Identity','Crypto wallet','Malware','Leak','Infrastructure']},
};
export function IntelligenceWorkspace({kind}:{kind:Workspace}) {
  const config=CONFIG[kind];
  const {counts,feeds,error:metadataError}=useIntelligenceMetadata();
  const {state,health}=useLive();
  const [query,setQuery]=useState('');
  const [simulated,setSimulated]=useState<Scenario|null>(null);
  const [result,setResult]=useState<RelatedThreat[]|null>(null);
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState<string|null>(null);
  const [selected,setSelected]=useState<string|null>(null);
  const [onlySource,setOnlySource]=useState(false);
  const dark=feeds?.feeds.find(f=>f.name==='darkweb');
  const graph=useMemo(()=>graphFromPaths((result??[]).map(r=>r.path)),[result]);
  const schema: IntelligenceNode[]=config.schema.map((label,i)=>({id:`schema-${i}`,label,kind:'Research role',detail:'Illustrative research object. Run an indicator lookup to inspect observed evidence.',color:kind==='malware'?'#a855f7':undefined}));
  const labels: readonly string[] = config.labels;
  const rows=(result??[]).filter(r=>kind==='dark-web' ? !onlySource || r.sources.some(s=>/darkweb|dark.web/i.test(s)) : labels.includes(r.label)||r.path.some(p=>labels.includes(p.label)));
  const selectedNode=graph.nodes.find(n=>n.id===selected);
  const selectedThreat=(result??[]).find(r=>r.threat_id===selected || r.path.some(p=>p.node_id===selected));
  const count=counts?config.countKeys.reduce((total,k)=>total+(counts[k]??0),0):null;
  const asset=Object.values(state.nodes).find(n=>n.level==='critical'&&n.device.ip)??Object.values(state.nodes).find(n=>n.device.ip);
  const submit=async(e:FormEvent)=>{e.preventDefault();setLoading(true);setError(null);setSelected(null);try{setResult(await api.relatedThreats(query.trim()));setSimulated(scenarioFor(query,isHostedMode()));}catch(e){setResult(null);setSimulated(null);setError(e instanceof Error?e.message:String(e));}finally{setLoading(false);}};
  return <div className={`analyst-workspace workspace-${kind}`}><PageHeader title={config.title} subtitle={config.description} />
    <div className="workspace-command-line"><span className="section-eyebrow">{config.eyebrow}</span><span className="technical-badge">{kind==='dark-web'?`SOURCE / ${dark?.mode?.toUpperCase()??'UNAVAILABLE'}`:'READ-ONLY / GRAPH EVIDENCE'}</span></div>
    <div className="workspace-metrics"><div><span>{kind==='dark-web'?'Source feed objects':'Graph inventory objects'}</span><strong>{kind==='dark-web'?dark?.last_run?.objects??'—':count??'—'}</strong></div><div><span>Lookup results</span><strong>{result?result.length:'—'}</strong></div><div><span>{kind==='dark-web'?'Last successful sync':'Relationships in view'}</span><strong className={kind==='dark-web'?'metric-timestamp':''}>{kind==='dark-web'?(dark?.last_success_at?new Date(dark.last_success_at).toLocaleString():'Never'):result?graph.edges.length:'—'}</strong></div><div><span>Evidence source</span><strong className="metric-word">{kind==='dark-web'?dark?.last_run?.status??'Unavailable':result?'Returned paths':'Awaiting lookup'}</strong></div></div>
    <form className="workspace-query panel" onSubmit={submit}><label htmlFor={`${kind}-indicator`}>INDICATOR RECONNAISSANCE</label><div><span className="terminal-prompt" aria-hidden="true">&#10095;</span><input id={`${kind}-indicator`} className="input" aria-label={`${kind} indicator`} value={query} onChange={e=>setQuery(e.target.value)} placeholder="IP / DOMAIN / HASH / URL" maxLength={2000} /><button className="btn command-action" disabled={!query.trim()||loading}>{loading?'Correlating...':'Correlate indicator'}</button></div>{asset&&<button className="observed-query" type="button" onClick={()=>setQuery(asset.device.ip!)}>Use observed asset IP: {asset.device.ip}</button>}{health?.deployment==='hosted'&&<button className="observed-query" type="button" onClick={()=>setQuery(SIM_IOC)}>Use simulated indicator: {SIM_IOC}</button>}</form>
    {(error||metadataError)&&<p className="workspace-error" role="alert">{error??metadataError}</p>}
    <div className="workspace-main"><section className="panel workspace-network"><div className="command-section-title"><div><span className="section-eyebrow">{result?'OBSERVED RELATIONSHIPS':'RESEARCH SCHEMA'}</span><h2>{kind==='dark-web'?'Hidden network signals':kind==='actors'?'Actor relationship graph':'Malware evidence graph'}</h2></div></div><NexusScene title={`${config.title} relationship visualization`} mode={kind==='malware'?'specimen':'network'} nodes={result?graph.nodes:schema} edges={result?graph.edges:[]} selected={selected} onSelect={setSelected} illustrative={!result} caption={result?'GRAPH EVIDENCE / RETURNED PATHS':'ILLUSTRATIVE RESEARCH ROLES'} />{result&&result.length===0&&<p className="workspace-empty">No relationships were returned for this indicator.</p>}</section>
      <aside className="panel intelligence-inspector"><span className="section-eyebrow">INTELLIGENCE / EVIDENCE BRIEFING</span><h2>{selectedNode?.label??'Follow the evidence.'}</h2>{selectedNode?<><span className="technical-badge">{selectedNode.kind}</span><p className="font-mono break-all">{selectedNode.id}</p>{selectedThreat&&<dl><dt>Source</dt><dd>{selectedThreat.sources.join(', ')||'Not supplied'}</dd><dt>Confidence</dt><dd>{selectedThreat.confidence??'Not supplied'}</dd><dt>Relationship hops</dt><dd>{selectedThreat.hops}</dd><dt>Indicator freshness</dt><dd>{selectedThreat.indicator_stale?'Stale':'Not marked stale'}</dd></dl>}</>:<p>Select an object in the graph to inspect its identity and source metadata. {result?'These relationships were returned by the configured intelligence graph.':'The scene currently shows research roles, not observed actors or incidents.'}</p>}<Link className="public-text-link" to="/threat-intel">Open intelligence workbench &#8594;</Link><div className="analyst-note"><span className="section-eyebrow">ANALYST NOTE</span><p>{kind==='actors'?'An association is not an attribution. Assess provenance and corroboration before assigning responsibility.':kind==='dark-web'?'Feed mode is shown above. Mock source objects are research fixtures, not claims of real underground activity.':'Malware names and indicators are graph objects. A relationship is context, not proof that an asset is infected.'}</p></div></aside>
    </div>
    <section className="panel workspace-results"><div className="command-section-title"><div><span className="section-eyebrow">EVIDENCE / RETURNED OBJECTS</span><h2>{kind==='actors'?'Actor associations':kind==='malware'?'Malware associations':'Source-correlated intelligence'}</h2></div>{kind==='dark-web'&&<label><input type="checkbox" checked={onlySource} onChange={e=>setOnlySource(e.target.checked)} /> Dark-web sources only</label>}</div><div className="overflow-x-auto"><table><thead><tr><th>Entity</th><th>Class</th><th>Source</th><th>Confidence</th><th>Hops</th><th>Freshness</th></tr></thead><tbody>{rows.map(r=><tr key={r.threat_id} tabIndex={0} onClick={()=>setSelected(r.threat_id)} onKeyDown={e=>e.key==='Enter'&&setSelected(r.threat_id)}><td><strong>{r.name??r.threat_id}</strong><small>{r.external_id??r.threat_id}</small></td><td><span className="technical-badge">{r.label}</span></td><td>{r.sources.join(', ')||'Not supplied'}</td><td>{r.confidence??'—'}</td><td>{r.hops}</td><td>{r.indicator_stale?'Stale':'Not marked stale'}</td></tr>)}</tbody></table></div>{!rows.length&&<div className="workspace-empty">{result?`No matching ${kind==='actors'?'actor':kind==='malware'?'malware':'source'} objects in this lookup.`:'Enter an indicator to load observed relationships.'}</div>}</section>
    {simulated&&result&&<SimInvestigation scenario={simulated} />}
    {kind==='dark-web'&&<div className="workspace-feed-health"><FeedHealth /></div>}
  </div>;
}
