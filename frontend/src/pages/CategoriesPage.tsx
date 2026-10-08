import { Link, useSearchParams } from "react-router";
import { useIntelligenceMetadata } from "../hooks/useIntelligenceMetadata";
import { WorldWindow } from "../components/WorldWindow";
import { TAXONOMY } from "../visuals/model";
const CATEGORIES=[
  {id:'dark-web',label:'Dark web',kind:'Infrastructure',detail:'Source mentions, provenance and correlated indicators from configured dark-web feeds.',to:'/dark-web',count:null},
  {id:'malware',label:'Malware',kind:'Malware',detail:TAXONOMY[2]!.detail,to:'/malware',count:'Malware'},
  {id:'vulnerabilities',label:'Vulnerabilities',kind:'Vulnerability',detail:TAXONOMY[6]!.detail,to:'/vulnerabilities',count:'Vulnerability'},
  {id:'actors',label:'Threat actors',kind:'ThreatActor',detail:'Research actor and intrusion-set associations through the observed intelligence graph.',to:'/actors',count:'IntrusionSet'},
  {id:'identities',label:'Identities',kind:'Identity',detail:TAXONOMY[3]!.detail,to:'/threat-intel',count:'Identity'},
  {id:'crypto',label:'Crypto',kind:'Ledger',detail:TAXONOMY[4]!.detail,to:'/threat-intel',count:null},
  {id:'trafficking',label:'Trafficking',kind:'Network',detail:TAXONOMY[5]!.detail,to:'/threat-intel',count:null},
  {id:'infrastructure',label:'Infrastructure',kind:'Infrastructure',detail:'Map observable endpoints and related infrastructure through indicator evidence.',to:'/threat-intel',count:'Observable'},
  {id:'weapons',label:'Weapons',kind:'Evidence',detail:TAXONOMY[0]!.detail,to:'/threat-intel',count:null},
  {id:'narcotics',label:'Narcotics',kind:'Evidence',detail:TAXONOMY[1]!.detail,to:'/threat-intel',count:null},
];
export function CategoriesPage(){
  const [params,setParams]=useSearchParams();
  const {counts}=useIntelligenceMetadata();
  const category=CATEGORIES.find(c=>c.id===params.get('category'))??CATEGORIES[0]!;
  return <div className="category-explorer public-section"><p className="section-eyebrow">INTELLIGENCE EXPLORER / RESEARCH TAXONOMY</p><h1>Understand the<br /><span>invisible ecosystem.</span></h1><p className="public-lede">Explore the subjects of intelligence. Enter an analyst workspace to examine measured evidence.</p><div className="category-workbench"><nav aria-label="Intelligence categories">{CATEGORIES.map(c=><button key={c.id} aria-pressed={category.id===c.id} onClick={()=>setParams({category:c.id})}><span>{c.label}</span><span>{c.count&&counts?counts[c.count]??0:'—'}</span></button>)}</nav><div className="category-stage"><WorldWindow caption={`${category.label.toUpperCase()} / FORENSIC FIELD`} /><article className="category-briefing"><span className="section-eyebrow">THREAT CLASS / {category.label.toUpperCase()}</span><h2>{category.label} intelligence</h2><p>{category.detail}</p><dl><div><dt>Risk level</dt><dd>Unassessed</dd></div><div><dt>{category.count==='Observable'?'Observable graph objects':category.count==='IntrusionSet'?'Intrusion-set graph objects':'Graph objects'}</dt><dd>{category.count&&counts?counts[category.count]??0:'Not measured'}</dd></div></dl><Link to={category.to} className="public-text-link">Open analyst workspace &#8599;</Link></article></div></div><p className="data-provenance">Research categories do not imply live coverage. Graph counts reflect stored objects; source mode and provenance are available in the analyst workspace.</p></div>;
}
