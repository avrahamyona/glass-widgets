// No-Electron: extracts the LIVE fitAckBody from src/lib/agent.js and drives it with fixtures.
const assert=require('assert'),fs=require('fs'),path=require('path');
const src=fs.readFileSync(path.join(__dirname,'..','src','lib','agent.js'),'utf8');
const start=src.indexOf('function fitAckBody(body){');assert(start>=0,'fitAckBody found');
let depth=0,i=src.indexOf('{',start);const j0=i; // brace-match the function body
for(;i<src.length;i++){if(src[i]==='{')depth++;else if(src[i]==='}'){depth--;if(!depth)break}}
const body=src.slice(start,i+1);
const auditLog=[];
const fn=new Function('audit',body+';return fitAckBody;');
const fit=fn(o=>auditLog.push(o));

const mk=(over={})=>({key:'k',id:'id1',status:'done',note:'ok',...over});
const check=(body,label)=>{
 const wire=fit(body);
 const parsed=JSON.parse(wire);
 assert(wire.length<=3900,label+': raw body <=3900, got '+wire.length);
 if(parsed.result)assert(JSON.stringify(parsed.result).length<=3500,label+': result <=3500, got '+JSON.stringify(parsed.result).length);
 return parsed;
};

// 1) small body passes through untouched
{const b=mk({result:{stdout:'GWOK',stderr:'',exit:0}});const p=check(b,'small');assert(p.result.stdout==='GWOK'&&!p.result.truncated,'small result untouched')}

// 2) escape-heavy result stdout (quotes): 3530 raw -> serialized over 3500 must shrink with metadata
{const q='"'.repeat(3530);const b=mk({result:{stdout:q,stderr:'',exit:0}});const p=check(b,'quotes');
 assert(p.result.truncated===true&&+p.result.stdout_full===3530,'quotes truncation metadata: '+JSON.stringify({t:p.result.truncated,f:p.result.stdout_full}));
 assert(p.result.stdout.length<3530,'stdout actually shrunk')}

// 3) control chars (worst-case 6x escaping)
{const c=String.fromCharCode(1).repeat(1200);const p=check(mk({result:{stdout:c,stderr:'',exit:0}}),'control-chars');assert(p.result.truncated===true,'control-chars truncated')}

// 4) result-only oversize with plain chars (result >3500, body would be under)
{const a='a'.repeat(3600);const p=check(mk({result:{stdout:a,stderr:'',exit:0}}),'result-oversize');assert(p.result.truncated===true,'result-oversize truncated')}

// 5a) large note (1000) + shrinkable stdout: stdout shrink alone fits -> note PRESERVED (documented preference)
{const a='a'.repeat(3600);const b=mk({note:'n'.repeat(1000),result:{stdout:a,stderr:'',exit:0}});const p=check(b,'large-note-shrinkable');
 assert(String(p.note).length===1000&&p.result.truncated===true,'stdout shrink preferred, note preserved')}
// 5b) large note (1000) + non-shrinkable result: note contribution bounded explicitly, result stubbed
{const b=mk({note:'n'.repeat(1000),result:{blob:'b'.repeat(3600)}});const p=check(b,'large-note-stub');
 assert(String(p.note).length<=200,'note bounded to 200, got '+String(p.note).length);
 assert(p.result&&p.result.guard===true,'result stubbed')}

// 6) matches array (find_files shape) via the FULL ack path: shrink marks entry loss explicitly
{
 // the ack path is a commit/verify/send CLUSTER (canon -> durable commit -> wire send): extract all four
 const grab=sig=>{const st=src.indexOf(sig);assert(st>=0,sig+' found');let dd=0,ii=src.indexOf('{',st);for(;ii<src.length;ii++){if(src[ii]==='{')dd++;else if(src[ii]==='}'){dd--;if(!dd)break}}return src.slice(st,ii+1)};
 globalThis.__ackSrc=['function canonAckResult(result){','function ackCommit(id,status,note,canon){','async function ackSend(id,status,note,canon){','async function ack(id,status,note,result){'].map(grab).join('\n');
}
const mkAck=(onSend)=>{let sent=null;const audits=[];
 const {capResult,RESULT_CAP}=require('../src/lib/ledger.js');
 const fn=new Function('cmdKey','CAPS','audit','fitAckBody','ackUrl','fetch','capResult','RESULT_CAP','ledger',globalThis.__ackSrc+';return ack;')
 ('k',{noteLen:2000,resultLen:3000},o=>audits.push(o),fit,'http://x/ack',
  async(u,o)=>{sent=o.body;return {ok:true,text:async()=>'{"updated":1}' }},capResult,RESULT_CAP,{has:()=>false,put:()=>true});
 return {fn,getSent:()=>sent,audits}};


// 7) generic oversize result WITHOUT stdout field: stub replacement
{const big={blob:'b'.repeat(5000)};const p=check(mk({result:big}),'generic');assert(p.result&&p.result.guard===true,'generic result stubbed with guard metadata')}

// 8) still-oversize pathological (huge id+key+note, stub cannot save): audited AND no wire to send
{auditLog.length=0;const b=mk({id:'i'.repeat(5000),note:'n'.repeat(5000),result:{blob:'b'.repeat(5000)}});const wire=fit(b);
 assert(wire===null,'unfittable body yields NO wire (never transmitted blind)');
 assert(auditLog.some(l=>l.kind==='ack'&&l.stage==='envelope_fail'),'unfittable envelope audited: '+JSON.stringify(auditLog))}

// 9) extracted ack integration: on an unfittable body the fetch is NEVER called
{
 let fetches=0;const audits2=[];
 const {capResult,RESULT_CAP}=require('../src/lib/ledger.js');
 const ackFn=new Function('cmdKey','CAPS','audit','fitAckBody','ackUrl','fetch','capResult','RESULT_CAP','ledger',
  globalThis.__ackSrc+';return ack;')('k',{noteLen:2000,resultLen:3000},o=>audits2.push(o),fit,'http://x/ack',
  async()=>{fetches++;return {ok:true,text:async()=>'{"updated":1}'}},capResult,RESULT_CAP,{has:()=>false,put:()=>true});
 (async()=>{
  await ackFn('i'.repeat(5000),'done','n'.repeat(5000),{blob:'b'.repeat(5000)});
  assert(fetches===0,'unfittable body: fetch NOT called, got '+fetches);
  assert(auditLog.some(l=>l.kind==='ack'&&l.stage==='envelope_fail'),'envelope_fail audited on the ack path (fit-level audit sink): '+JSON.stringify(auditLog.slice(-3)));
  await ackFn('ok1','done','ok',{stdout:'GWOK',stderr:'',exit:0});
  assert(fetches===1,'fittable body: fetch called exactly once');
  // 6b) matches through the full ack path: entries shrink with explicit loss metadata
  const big=Array.from({length:50},(_,i)=>({path:'/x/'.repeat(30)+i}));
  await ackFn('m1','done','ok',{matches:big});
  // fetch mock above does not capture body; use mkAck for the capture
  const cap=mkAck();await cap.fn('m2','done','ok',{matches:big});
  const wire=JSON.parse(cap.getSent());
  assert(wire.result.matches.length<50,'matches shrunk on the ack path');
  assert(wire.result.truncated===true&&wire.result.matches_full===50,'matches loss marked: '+JSON.stringify({t:wire.result.truncated,f:wire.result.matches_full}));
  // 6c) shape-safe canonical: null / primitive / cyclic / function results never crash the ack path
  const sN=mkAck();await sN.fn('n1','done','ok',null);
  assert(JSON.parse(sN.getSent()).result.value===null,'null result wrapped into a stable shape');
  const sP=mkAck();await sP.fn('p1','done','ok',42);
  assert(JSON.parse(sP.getSent()).result.value===42,'primitive result wrapped');
  const cyc={a:1};cyc.self=cyc;const sC=mkAck();await sC.fn('c1','done','ok',cyc);
  assert(JSON.parse(sC.getSent()).result.unserializable===true,'cyclic result marked unserializable');
  const sF=mkAck();await sF.fn('f1','done','ok',function(){return 1});
  assert(JSON.parse(sF.getSent()).result.unserializable===true,'function result marked unserializable');
  console.log('AGENT-ACK-UNIT: PASS');
 })().catch(e=>{console.error('FAIL',e);process.exit(1)});
}
