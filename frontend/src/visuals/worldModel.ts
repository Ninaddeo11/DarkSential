export type ArtifactKind = 'handgun' | 'rifle' | 'case' | 'package' | 'capsules' | 'cargo' | 'vehicle' | 'server' | 'phone' | 'terminal' | 'crypto' | 'identity' | 'malware' | 'fragment';
export type WorldLayer = 'landing' | 'intelligence' | 'about' | 'access' | 'operations';
export interface ThreatArtifact {
  id: string;
  type: ArtifactKind;
  category: string;
  position: [number, number, number];
  rotation: [number, number, number];
  velocity: [number, number, number];
  scale: number;
  amplitude: number;
  frequency: number;
  opacity: number;
  accent: string;
}

/** Fictional research artifacts. Coordinates describe a stage, never geography. */
export const WORLD_ARTIFACTS: ThreatArtifact[] = [
  {id:'w-01',type:'handgun',category:'weapons',position:[4.4,1.2,2],rotation:[.12,-.38,-.24],velocity:[.012,0,.006],scale:1.95,amplitude:.15,frequency:.16,opacity:1,accent:'#a56877'},
  {id:'w-02',type:'rifle',category:'weapons',position:[-8.7,4.4,-9],rotation:[.15,.28,-.22],velocity:[.008,0,.004],scale:1.5,amplitude:.12,frequency:.11,opacity:.6,accent:'#7b4853'},
  {id:'e-01',type:'case',category:'weapons',position:[-3.4,-3.7,-5],rotation:[.3,.5,.16],velocity:[-.009,0,.008],scale:1.2,amplitude:.15,frequency:.14,opacity:.55,accent:'#477d8b'},
  {id:'n-01',type:'package',category:'narcotics',position:[1.7,-2.1,1],rotation:[.22,-.3,-.16],velocity:[.006,0,.009],scale:1.5,amplitude:.18,frequency:.13,opacity:1,accent:'#ad82ba'},
  {id:'n-02',type:'capsules',category:'narcotics',position:[-5.5,2.6,-12],rotation:[.4,.7,.3],velocity:[.009,0,.003],scale:1.2,amplitude:.12,frequency:.1,opacity:.48,accent:'#8c71a3'},
  {id:'t-01',type:'cargo',category:'trafficking',position:[7.4,-2.6,-2],rotation:[.18,-.5,.08],velocity:[-.008,0,.007],scale:1.35,amplitude:.1,frequency:.12,opacity:1,accent:'#a5794b'},
  {id:'t-02',type:'vehicle',category:'trafficking',position:[-7.3,-3.8,-15],rotation:[.07,.35,.08],velocity:[.006,0,.003],scale:1.4,amplitude:.1,frequency:.09,opacity:.5,accent:'#506571'},
  {id:'s-01',type:'server',category:'infrastructure',position:[8.8,3.8,-7],rotation:[.12,-.48,-.08],velocity:[.008,0,.004],scale:1.35,amplitude:.16,frequency:.11,opacity:1,accent:'#397f99'},
  {id:'s-02',type:'server',category:'infrastructure',position:[-.5,5.4,-14],rotation:[0,.3,-.12],velocity:[-.006,0,.004],scale:1.35,amplitude:.16,frequency:.09,opacity:.48,accent:'#335666'},
  {id:'s-03',type:'phone',category:'infrastructure',position:[5.6,4.5,.2],rotation:[.2,.4,-.16],velocity:[.008,0,.004],scale:1.25,amplitude:.18,frequency:.13,opacity:1,accent:'#4ea2b2'},
  {id:'s-04',type:'terminal',category:'infrastructure',position:[-10,-2,4],rotation:[.12,.65,.14],velocity:[.008,0,.002],scale:1.9,amplitude:.12,frequency:.1,opacity:.6,accent:'#447c8e'},
  {id:'c-01',type:'crypto',category:'crypto',position:[10.4,.6,-2],rotation:[.2,-.6,.14],velocity:[-.007,0,.005],scale:1.35,amplitude:.13,frequency:.15,opacity:1,accent:'#9f946d'},
  {id:'c-02',type:'crypto',category:'crypto',position:[-7,-4.8,6],rotation:[.3,.5,.3],velocity:[.009,0,.003],scale:1.9,amplitude:.15,frequency:.1,opacity:.58,accent:'#617a87'},
  {id:'i-01',type:'identity',category:'identities',position:[3.4,3.8,-9],rotation:[.14,-.25,.24],velocity:[.006,0,.003],scale:1.25,amplitude:.13,frequency:.1,opacity:.65,accent:'#4e8796'},
  {id:'m-01',type:'malware',category:'malware',position:[4,-.1,-7],rotation:[.5,.3,.2],velocity:[.007,0,.005],scale:1.25,amplitude:.18,frequency:.13,opacity:.85,accent:'#836b9e'},
  {id:'x-01',type:'fragment',category:'exploits',position:[10,-4.7,-9],rotation:[.5,.2,.4],velocity:[.006,0,.007],scale:1.5,amplitude:.15,frequency:.11,opacity:.6,accent:'#965260'},
];

export function worldLayer(pathname: string): WorldLayer {
  if(pathname==='/about')return 'about';
  if(pathname==='/intelligence')return 'intelligence';
  if(pathname==='/access'||pathname==='/login')return 'access';
  if(pathname==='/'||pathname==='/landing')return 'landing';
  return 'operations';
}

export function visibleArtifacts(tier: 'mobile'|'tablet'|'desktop') {
  if(tier==='desktop')return WORLD_ARTIFACTS;
  const ids=tier==='mobile'?['w-01','n-01','t-01','s-01','c-01','m-01']:['w-01','w-02','n-01','t-01','s-01','s-03','c-01','i-01','m-01','x-01'];
  return WORLD_ARTIFACTS.filter(a=>ids.includes(a.id));
}
