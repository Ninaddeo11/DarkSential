import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const config=JSON.parse(await fs.readFile('../vercel.json','utf8'));
const headers=config.services.frontend.headers[0].headers.map(({key,value})=>({name:key,value}));
const tabs=await(await fetch('http://127.0.0.1:9224/json')).json();
const ws=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);
await new Promise(r=>ws.addEventListener('open',r,{once:true}));
let seq=0;const pending=new Map(),securityErrors=[];
const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
ws.addEventListener('message',async e=>{
  const m=JSON.parse(e.data);
  if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(m.error):p.resolve(m.result);}
  if(m.method==='Log.entryAdded'&&m.params.entry.source==='security'&&m.params.entry.level==='error')securityErrors.push(m.params.entry.text);
  if(m.method==='Fetch.requestPaused'){
    const p=m.params;
    await call('Fetch.continueResponse',{requestId:p.requestId,responseCode:p.responseStatusCode,responseHeaders:[...(p.responseHeaders??[]).filter(h=>!headers.some(n=>n.name.toLowerCase()===h.name.toLowerCase())),...headers]});
  }
});
await Promise.all([call('Page.enable'),call('Runtime.enable'),call('Log.enable')]);
await call('Fetch.enable',{patterns:[{resourceType:'Document',requestStage:'Response',urlPattern:'*'}]});
await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
const base=process.argv[2]||'http://127.0.0.1:4175';
for(const path of ['/','/about','/access','/overview']){
  await call('Page.navigate',{url:base+path});
  let loaded=false;
  for(let i=0;i<30;i++){
    await new Promise(r=>setTimeout(r,300));
    const r=await call('Runtime.evaluate',{expression:`Boolean(document.querySelector('h1')&&document.querySelector('.dark-web-environment canvas'))`,returnByValue:true});
    if(r.result.value){loaded=true;break;}
  }
  assert.equal(loaded,true,`CSP blocked ${path}`);
}
await call('Fetch.disable');
assert.deepEqual(securityErrors,[]);
console.log('Production CSP passed: landing, About, Access and workspace deep links render with Vercel response headers.');
ws.close();
