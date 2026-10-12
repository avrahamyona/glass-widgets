// Unit tests for the unified tunnel intake ledger (lifecycle, schema, caps, replay-eviction safety).
const assert=require('assert'),fs=require('fs'),path=require('path');
const {createLedger,RESULT_CAP,MAX_LIVE,SCHEMA_V}=require('../src/lib/ledger.js');
const dir=fs.mkdtempSync('/tmp/gw-ledger-unit-');const F=path.join(dir,'ledger.json');
const now=Date.now();

// lifecycle: accepted -> running -> terminal; terminal is final
let l=createLedger(F);
assert(l.put('cmd-1',{status:'accepted',exp:now+300000})===true,'put accepted');
assert(l.get('cmd-1').status==='accepted'&&l.get('cmd-1').terminal===false,'accepted, not final');
assert(l.transition('cmd-1','running')===true,'accepted -> running');
assert(l.get('cmd-1').status==='running','running recorded');
assert(l.put('cmd-1',{status:'done',note:'ok',result:{n:1}})===true,'terminal');
assert(l.get('cmd-1').terminal===true&&l.get('cmd-1').status==='done','done is final');
assert(l.put('cmd-1',{status:'failed',note:'late'})===true&&l.get('cmd-1').status==='done','terminal never rewritten');
assert(l.transition('cmd-1','running')===false&&l.get('cmd-1').status==='done','final record: NO transition permit (an effect must never (re)start)');
assert(l.transition('never-existed','running')===false,'missing record: no durable record = no permit');
// result kept 24h regardless of the envelope exp
{const r=l.get('cmd-1');assert(r.resultExp>now+23*3600*1000&&r.dedupExp===now+300000,'envelope exp bounds dedup only; result retention is 24h')}
// durability + crash reconciliation: non-final records become UNKNOWN on reload, never retried
l.put('cmd-2',{status:'accepted',exp:now+300000});
l=createLedger(F);
{const r=l.get('cmd-2');assert(r.status==='unknown'&&r.terminal===true,'crashed mid-flight -> unknown (evidence)')}
assert(l.put('cmd-2',{status:'done',note:'late ack'})===true&&l.get('cmd-2').status==='unknown','unknown is final - never overwritten, never auto-retried');
assert(l.has('cmd-2')===true,'unknown still dedups (replay -> 409 at intake)');
// prune: dead dedup window + dead result window only
l=createLedger(F);
assert(l.put('cmd-3',{status:'accepted',exp:now-1000})===true,'put accepted (already past envelope exp)');
assert(l.get('cmd-3')!==null,'non-final past-exp record remains until restart reconciliation');
l=createLedger(F); // reload converts to unknown with fresh 24h result retention
assert(l.get('cmd-3').status==='unknown','reloaded past-exp accepted -> unknown');
// strict ids
for(const bad of ['__proto__','constructor','prototype','a b','x'.repeat(81),'',null,42])assert(l.put(bad,{status:'accepted',exp:now+1000})===false,'bad id refused: '+String(bad));
assert(l.get('__proto__')===null&&!l.has('__proto__'),'proto id never reads');
// result capping (bytes)
l.put('cmd-4',{status:'done',note:'big',result:{blob:'x'.repeat(RESULT_CAP*3)}});
{const r=l.get('cmd-4');assert(r.result&&r.result.truncated===true&&r.result.full_bytes>RESULT_CAP,'oversize result capped (metadata), not raw')}
// REPLAY-VIA-EVICTion (ops repro): a saturated live set REFUSES new intake - live tombstones are never evicted
{const l2=createLedger(path.join(dir,'l2.json'));
 for(let i=0;i<MAX_LIVE;i++)assert(l2.put('live-'+i,{status:'accepted',exp:now+300000})===true,'fill live '+i);
 assert(l2.put('live-new',{status:'accepted',exp:now+300000})==='full','live window saturated -> full (caller 429s)');
 assert(l2.get('live-0')!==null,'the OLDEST live tombstone survives - its envelope can never re-run');
 // terminal results may be stripped under byte pressure, tombstones stay
 const l3=createLedger(path.join(dir,'l3.json'));
 for(let i=0;i<MAX_LIVE;i++)l3.put('b-'+i,{status:'accepted',exp:now+1000});
 for(let i=0;i<60;i++)l3.put('b-'+i,{status:'done',note:'x'.repeat(150),result:{blob:'y'.repeat(1800)}});
 for(let i=0;i<MAX_LIVE;i++){const r=l3.get('b-'+i);assert(r!==null&&r.dedupExp===now+1000,'tombstone survives byte pressure: b-'+i)}
}
// note truncation is by BYTES (Hebrew): a 200-char Hebrew note must still pass the byte cap
{const l4=createLedger(path.join(dir,'l4.json'));
 const note='אב'.repeat(150); // 300 chars, 600 bytes
 assert(l4.put('he-1',{status:'accepted',exp:now+300000})===true);
 assert(l4.put('he-1',{status:'done',note,result:{ok:1}})===true,'Hebrew note does not fail the terminal write');
 const r=l4.get('he-1');assert(Buffer.byteLength(r.note)<=200,'note byte-capped: '+Buffer.byteLength(r.note))}
// byte-capacity: dead-window terminals are evicted by BYTES until the file fits; live tombstones stay
{const l5=createLedger(path.join(dir,'l5.json'));
 for(let i=0;i<1500;i++)l5.put('d-'+i,{status:'accepted',exp:now-1000}); // dead dedup window
 for(let i=0;i<1500;i++)l5.put('d-'+i,{status:'done',note:'z'.repeat(190),result:{blob:'q'.repeat(900)}});
 for(let i=0;i<10;i++)l5.put('live-'+i,{status:'accepted',exp:now+300000});
 const p=path.join(dir,'l5.json');
 assert(fs.statSync(p).size<=256*1024,'file within 256KB: '+fs.statSync(p).size);
 for(let i=0;i<10;i++)assert(l5.get('live-'+i)!==null,'live tombstone survives byte eviction: live-'+i)}
// strict cross-field schema on load
const badRec=(o)=>{fs.writeFileSync(F,JSON.stringify({'cmd-x':{v:SCHEMA_V,status:'done',note:'',at:1,dedupExp:now+100000,resultExp:now+100000,terminal:true,...o}}));return createLedger(F).ok()};
assert(badRec({})===true,'valid record loads');
assert(badRec({status:'accepted'})===false,'accepted with terminal:true -> store down (cross-field)');
assert(badRec({status:'done',terminal:false})===false,'done with terminal:false -> down');
assert(badRec({result:{blob:'x'.repeat(RESULT_CAP+300)}})===false,'oversize stored result -> down');
assert(badRec({at:1.5})===false,'non-integer timestamp -> down');
assert(badRec({v:2})===false,'unknown schema version -> down');
fs.writeFileSync(F,JSON.stringify({'cmd-x':{v:SCHEMA_V,status:'accepted',note:'',at:1,dedupExp:now+100000,resultExp:now+100000,terminal:false,result:{leak:1}}}));
assert(createLedger(F).ok()===false,'non-final record carrying a result -> down');
// ATOMIC commit: a failed persist leaves the ENTIRE live map untouched (not just the current id)
{const d2=fs.mkdtempSync('/tmp/gw-ledger-ro-'),f2=path.join(d2,'l.json');
 const l6=createLedger(f2);
 l6.put('ro-1',{status:'accepted',exp:now+300000});
 l6.put('ro-2',{status:'done',note:'ok',result:{n:1}});
 fs.chmodSync(d2,0o555); // disk write must now fail
 const r=l6.put('ro-3',{status:'accepted',exp:now+300000});
 assert(r===false&&l6.ok()===false,'failed persist: refused, store down');
 assert(l6.get('ro-1')!==null&&l6.get('ro-1').status==='accepted','prior live record untouched');
 assert(l6.get('ro-2').status==='done'&&l6.get('ro-2').result.n===1,'prior terminal record untouched');
 assert(l6.get('ro-3')===null,'the failed candidate never entered the live map');
 fs.chmodSync(d2,0o755)}
// corrupt/down store refuses writes
fs.writeFileSync(F,'{corrupt');
l=createLedger(F);
assert(l.ok()===false&&l.put('c9',{status:'accepted',exp:now+1000})===false&&l.transition('c9','running')===false,'down store refuses all writes');
fs.writeFileSync(F,'null');
assert(createLedger(F).ok()===false,'null JSON -> down');
// no tmp litter
fs.writeFileSync(F,JSON.stringify({}));l=createLedger(F);l.put('a',{status:'accepted',exp:now+1000});
assert(fs.readdirSync(dir).filter(f=>f.startsWith('ledger.json')&&f.includes('.tmp')).length===0,'no tmp litter');
// reconcileUnknown: the INTENTIONAL recovery-only rewrite - a FINAL 'unknown' with NO effect
// evidence (result==null, e.g. a parked enroll that never executed) may resolve to a real terminal;
// done records, unknown-with-result, and missing ids are NEVER touched
{const d3=fs.mkdtempSync('/tmp/gw-ledger-recon-'),f3=path.join(d3,'l.json');
 let l7=createLedger(f3);
 l7.put('pk-1',{status:'accepted',note:'parked enroll',exp:now+300000});
 l7.put('fx-1',{status:'accepted',exp:now+300000});l7.put('fx-1',{status:'done',note:'real',result:{n:7}});
 l7=createLedger(f3); // a REAL reload: the parked accepted becomes FINAL unknown (crash evidence)
 assert(l7.get('pk-1').status==='unknown'&&l7.get('pk-1').terminal===true,'reload converts parked accepted to FINAL unknown');
 assert(l7.put('pk-1',{status:'failed',note:'x'})===true&&l7.get('pk-1').status==='unknown','a generic put NEVER rewrites FINAL');
 assert(l7.reconcileUnknown('pk-1',{status:'failed',note:'cancelled at restart'})===true,'no-effect unknown reconciles to a real terminal');
 assert(l7.get('pk-1').status==='failed'&&l7.get('pk-1').terminal===true,'reconciled record is a durable terminal');
 assert(createLedger(f3).get('pk-1').status==='failed','the reconcile survives a REAL reload');
 assert(l7.reconcileUnknown('fx-1',{status:'failed',note:'x'})===false&&l7.get('fx-1').status==='done','a real done record is never reconciled');
 assert(l7.reconcileUnknown('pk-1',{status:'done',note:'x'})===false,'already reconciled - no longer unknown');
 assert(l7.reconcileUnknown('nope',{status:'failed',note:'x'})===false,'missing id refuses');
 fs.writeFileSync(f3,JSON.stringify({'ev-1':{v:SCHEMA_V,status:'unknown',note:'crash',at:1,dedupExp:now+100000,resultExp:now+100000,terminal:true,result:{partial:1}}}));
 const l8=createLedger(f3);
 assert(l8.ok()===true&&l8.get('ev-1').status==='unknown','unknown-with-result loads as a valid record');
 assert(l8.reconcileUnknown('ev-1',{status:'failed',note:'x'})===false&&l8.get('ev-1').result.partial===1,'unknown carrying effect evidence is NEVER rewritten')}
console.log('AGENT-LEDGER-UNIT: PASS');
