// No-Electron regression tests: the LIVE chat:move / chat:passthrough handler
// source is extracted from src/main.js and driven with mocks.
const assert=require('assert'),fs=require('fs'),path=require('path');
const src=fs.readFileSync(path.join(__dirname,'..','src','main.js'),'utf8');
const start=src.indexOf('const moveLogLast=');assert(start>=0,'move block found');
const endMark="return {ok:true}}catch{return {ok:false}}});";
const end=src.indexOf(endMark,start);assert(end>=0,'passthrough block found');
const body=src.slice(start,end+endMark.length);

function makeWorld(){
 const audit=[];
 const registered={on:{},handle:{}};
 const ipcMain={on:(k,f)=>registered.on[k]=f,handle:(k,f)=>registered.handle[k]=f};
 const mkWin=(id,failures)=>{const w={calls:[],_f:failures||0,isDestroyed:()=>false,webContents:{id},setIgnoreMouseEvents(t,o){if(w._f-->0)throw new Error('setter boom');w.calls.push(t)}};return w};
 const primary=mkWin(7),comp=mkWin(9);
 const wins={chat:primary};const chatCompanions=new Map([[2,comp]]);
 const islandAuditId=()=> 'chat';
 const callerInstance=()=> 'chat';
 const agentAudit=o=>audit.push(o);
 const fn=new Function('ipcMain','islandAuditId','agentAudit','callerInstance','wins','chatCompanions','process','registered',
   body+';return {move:registered.on["chat:move"],pt:registered.handle["chat:passthrough"]};');
 const h=fn(ipcMain,islandAuditId,agentAudit,callerInstance,wins,chatCompanions,process,registered);
 return {audit,h,primary,comp};
}
const evW=w=>({sender:w.webContents}); // e.sender IS the webContents object in real IPC

// A) throwing setter must not poison the transition cache (ops reproduction)
{
 const w=makeWorld();w.primary._f=1; // first apply on the primary throws
 let r=w.h.pt(evW(w.primary),true);
 assert(r&&r.ok===false,'failed apply reports ok:false');
 assert(w.audit.filter(l=>l.kind==='island_passthrough').length===0,'throwing setter: zero transition lines, zero poisoned cache entries');
 w.audit.length=0;
 r=w.h.pt(evW(w.primary),true); // retry: setter now works
 assert(r&&r.ok===true,'retry succeeds');
 const lines=w.audit.filter(l=>l.kind==='island_passthrough');
 assert(lines.length===2,'retry logs BOTH window transitions (the poisoned-cache bug would log zero)');
 const pl=lines.find(l=>l.wid===7);
 assert(pl&&pl.src==='primary'&&pl.on===true&&pl.source==='island'&&pl.instance==='chat','line carries window identity/role/validated provenance');
 assert(lines.some(l=>l.wid===9&&l.src==='companion'),'companion transition logged with its own identity');
 w.audit.length=0;
 w.h.pt(evW(w.primary),true);w.h.pt(evW(w.primary),true);
 assert(w.audit.length===0,'same-state repeats add zero lines');
 w.h.pt(evW(w.primary),false);
 const off=w.audit.filter(l=>l.kind==='island_passthrough'&&l.on===false);
 assert(off.length===2,'transition off logs one line per window');
 assert(off.some(l=>l.src==='primary'&&l.wid===7)&&off.some(l=>l.src==='companion'&&l.wid===9),'per-window identity on both');
}

// B) strict move validation: no coercion (ops reproduction: x:"12",y:null must be rejected)
{
 const w=makeWorld();
 w.h.move(evW(w.primary),{x:'12',y:null,mode:'mini',over:true});
 w.h.move(evW(w.primary),{x:12,y:1,mode:'mini',over:'yes'});
 w.h.move(evW(w.primary),{x:12,y:1,mode:'open',over:true});
 w.h.move(evW(w.primary),{x:NaN,y:1,mode:'mini',over:true});
 w.h.move(evW(w.primary),{x:true,y:1,mode:'mini',over:true});
 assert(w.audit.filter(l=>l.kind==='island_move').length===0,'string/null/non-boolean/wrong-mode/non-finite all rejected');
 const realNow=Date.now;let t=1000;Date.now=()=>t;
 w.h.move(evW(w.primary),{x:12,y:3,mode:'mini',over:true});
 t+=10;w.h.move(evW(w.primary),{x:13,y:3,mode:'mini',over:true}); // inside throttle
 const lines=w.audit.filter(l=>l.kind==='island_move');
 assert(lines.length===1,'valid accepted, throttled twin dropped');
 assert(lines[0].budget>=0&&lines[0].src==='primary'&&lines[0].wid===7,'budget + provenance exposed per line');
 t+=300;w.h.move(evW(w.comp),{x:1,y:1,mode:'mini',over:false});
 assert(w.audit.filter(l=>l.kind==='island_move'&&l.wid===9).length===1,'companion source not suppressed by primary throttle');
 Date.now=realNow;
}

// C) per-source cap: exhaustion is said out loud once, then silence
{
 process.env.GLASSWIDGETS_MOVE_PROBE_MAX='2';
 const w=makeWorld();
 const realNow=Date.now;let t=5000;Date.now=()=>t;
 for(let i=0;i<5;i++){t+=300;w.h.move(evW(w.primary),{x:i,y:1,mode:'mini',over:true})}
 Date.now=realNow;
 const moves=w.audit.filter(l=>l.kind==='island_move');
 const caps=w.audit.filter(l=>l.kind==='island_move_cap');
 assert(moves.length===2,'cap honored per source');
 assert(moves[1].budget===0,'budget reaches 0 on the last admitted line');
 assert(caps.length===1&&caps[0].wid===7,'exhaustion announced exactly once - absence afterwards means sampling stopped');
 delete process.env.GLASSWIDGETS_MOVE_PROBE_MAX;
}
// D) env normalization: Infinity/negatives/fractions/junk/huge all normalize to a finite positive integer <= 1000
{
 const budgetFor=v=>{process.env.GLASSWIDGETS_MOVE_PROBE_MAX=v;const w=makeWorld();
  const realNow=Date.now;Date.now=()=>99999;w.h.move(evW(w.primary),{x:1,y:1,mode:'mini',over:true});Date.now=realNow;
  delete process.env.GLASSWIDGETS_MOVE_PROBE_MAX;
  const l=w.audit.find(l=>l.kind==='island_move');return l?l.budget:null};
 assert(budgetFor('3')===2,'small positive budget honored');
 assert(budgetFor('2.7')===1,'fraction floored');
 assert(budgetFor('Infinity')===999,'Infinity cannot remove the hard cap');
 assert(budgetFor('-1')===999,'negative rejected to default');
 assert(budgetFor('abc')===999,'junk rejected to default');
 assert(budgetFor('5000')===999,'huge values capped at 1000');
}
console.log('AGENT-AUDIT-UNIT: PASS');
