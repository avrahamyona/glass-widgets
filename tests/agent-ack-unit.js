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

// 6) matches array (find_files shape)
{const m=Array.from({length:50},(_,i)=>({path:'/x/'.repeat(30)+i}));const p=check(mk({result:{matches:m}}),'matches')}

// 7) generic oversize result WITHOUT stdout field: stub replacement
{const big={blob:'b'.repeat(5000)};const p=check(mk({result:big}),'generic');assert(p.result&&p.result.guard===true,'generic result stubbed with guard metadata')}

// 8) still-oversize pathological (huge id+key+note, stub cannot save): audited, not silent
{auditLog.length=0;const b=mk({id:'i'.repeat(5000),note:'n'.repeat(5000),result:{blob:'b'.repeat(5000)}});const wire=fit(b);
 assert(auditLog.some(l=>l.kind==='ack'&&l.stage==='envelope_fail'),'unfittable envelope audited: '+JSON.stringify(auditLog))}
console.log('AGENT-ACK-UNIT: PASS');
