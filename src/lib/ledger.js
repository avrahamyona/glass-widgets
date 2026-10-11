// The tunnel intake ledger ("החיים שלי השרתי" base): ONE durable, transactional record per
// command. At-most-once execution with durable evidence: the dedup tombstone outlives its
// envelope window NO MATTER WHAT (caps strip result payloads, never a live tombstone; a
// saturated live set REFUSES new intake with 'full'). Exactly-once across a crash cannot be
// claimed - a crash mid-effect leaves an 'unknown' record and the command is NEVER auto-retried.
//
// Lifecycle: accepted (committed at intake, BEFORE any effect) -> running (first effect starts)
// -> done/failed (terminal, final). On process start, any accepted/running record becomes
// 'unknown' (final): the effect may or may not have happened; reconciliation is manual and a new
// attempt needs a NEW command id. The envelope's exp bounds NEW EXECUTION AUTHORITY ONLY - it is
// never a deadline for keeping results.
//
// Retention (explicit): dedup tombstone until the envelope exp (after it, a replay is 403-expired
// at intake anyway); terminal/unknown results retained RESULT_TTL_MS (24h). Under byte pressure,
// terminal result payloads are stripped (oldest dead-window first) while the tombstone stays;
// under count pressure beyond MAX_ENTRIES, only dead-window terminal entries are evicted.
//
// Privacy note: result payloads are byte-CAPPED at write (RESULT_CAP) but a capped record can
// still hold private content (paths, clipboard text) - /task must stay behind signed-read auth.
//
// Discipline: strict cross-field schema on load - ANY invalid record = store DOWN (intake 503,
// /task 503); put on a down store refuses; unique-tmp + rename; strict ids.
const fs=require('fs');

const SCHEMA_V=1;
const RESULT_TTL_MS=24*3600*1000; // terminal/unknown result retention
const MAX_LIVE=200;       // live (in-window) dedup entries - past this, intake is 429'd
const MAX_ENTRIES=2000;   // total entries incl. retained terminals (dead-window eviction allowed)
const MAX_BYTES=256*1024,RESULT_CAP=2000,NOTE_CAP=200;
const STATUSES=new Set(['accepted','running','unknown','done','failed']);
const FINAL=new Set(['unknown','done','failed']); // never rewritten
const{ID_RE,strictId}=require('./command-contract'); // the shared strict contract - one source for ledger, verifiers and signer
// truncate to a BYTE cap without splitting a multibyte char (a 200-char Hebrew note is ~400 bytes)
function truncBytes(s,cap){s=String(s||'');if(Buffer.byteLength(s)<=cap)return s;
 return Buffer.from(s,'utf8').subarray(0,cap).toString('utf8').replace(/\uFFFD+$/,'')}

function validRec(r){
 if(!r||typeof r!=='object'||r.v!==SCHEMA_V)return false; // explicit schema version
 if(!STATUSES.has(r.status))return false;
 const fin=FINAL.has(r.status);
 if(r.terminal!==fin)return false; // cross-field consistency: status and terminal must agree
 if(!fin&&r.result!=null)return false; // no result before terminal
 if(typeof r.note!=='string'||Buffer.byteLength(r.note)>NOTE_CAP)return false;
 if(!Number.isInteger(r.at)||!Number.isInteger(r.dedupExp)||!Number.isInteger(r.resultExp))return false; // integer timestamps
 if(r.result!=null&&Buffer.byteLength(JSON.stringify(r.result))>RESULT_CAP)return false; // BYTE bounds == the write cap, not chars
 return true;
}
function capResult(result){
 if(result===undefined)return undefined;
 let s;try{s=JSON.stringify(result)}catch{return {truncated:true,unserializable:true}}
 if(Buffer.byteLength(s)<=RESULT_CAP)return result;
 return {truncated:true,full_bytes:Buffer.byteLength(s)}; // capped, NOT sanitized - still private
}

function createLedger(file){
 let ok=true;let tasks=new Map(); // strict ids only, insertion-ordered
 try{const j=JSON.parse(fs.readFileSync(file,'utf8'));
  if(!j||typeof j!=='object'||Array.isArray(j))throw new Error('bad ledger');
  for(const k of Object.keys(j)){
   if(!strictId(k)||!validRec(j[k]))throw new Error('bad record'); // strict schema: one bad record = store down
   const r=j[k];
   if(!FINAL.has(r.status)){r.status='unknown';r.terminal=true;r.result=null;r.resultExp=Date.now()+RESULT_TTL_MS} // crashed mid-flight: evidence, never retried
   if(+r.resultExp>Date.now()||+r.dedupExp>Date.now())tasks.set(k,r);
  }
 }catch(e){if(!e||e.code!=='ENOENT')ok=false} // missing file is fine; corrupt is not
 const live=now=>{let n=0;for(const v of tasks.values())if(+v.dedupExp>now)n++;return n};
 // shrink builds the candidate map on a COPY: pruning, stripping and eviction never touch the
 // live map. Returns {map,s} or null when the cap cannot be met even after every legal eviction
 // (the metadata of live entries alone exceeds MAX_BYTES). Records are never mutated in place
 // (put/transition/strip all set NEW objects), so a shallow map copy is a consistent snapshot.
 function shrink(cand){
  const now=Date.now();
  for(const[k,v]of cand)if(+v.dedupExp<=now&&+v.resultExp<=now)cand.delete(k); // prune dead windows
  if(cand.size>MAX_ENTRIES){ // count pressure: evict DEAD-WINDOW terminal entries only, oldest first
   const dead=[...cand.entries()].filter(([,v])=>+v.dedupExp<=now&&FINAL.has(v.status)).sort((a,b)=>(+a[1].at)-(+b[1].at));
   for(const[k]of dead){if(cand.size<=MAX_ENTRIES)break;cand.delete(k)}
  }
  let s=JSON.stringify(Object.fromEntries(cand));
  if(Buffer.byteLength(s)<=MAX_BYTES&&cand.size<=MAX_ENTRIES)return{map:cand,s};
  // byte pressure: strip terminal result payloads, oldest dead-window first - tombstones stay
  const strippable=[...cand.entries()].filter(([,v])=>v.result!=null&&FINAL.has(v.status))
   .sort((a,b)=>((+a[1].dedupExp>now)-(+b[1].dedupExp>now))||(+a[1].at)-(+b[1].at));
  for(const[k,v]of strippable){if(Buffer.byteLength(s)<=MAX_BYTES)break;cand.set(k,{...v,result:null});s=JSON.stringify(Object.fromEntries(cand))}
  // still over: evict whole DEAD-WINDOW terminal entries by bytes, oldest first (live tombstones never)
  if(Buffer.byteLength(s)>MAX_BYTES){
   const dead=[...cand.entries()].filter(([,v])=>+v.dedupExp<=now&&FINAL.has(v.status)).sort((a,b)=>(+a[1].at)-(+b[1].at));
   for(const[k]of dead){if(Buffer.byteLength(s)<=MAX_BYTES)break;cand.delete(k);s=JSON.stringify(Object.fromEntries(cand))}
  }
  return Buffer.byteLength(s)<=MAX_BYTES?{map:cand,s}:null;
 }
 // atomic commit: the candidate map becomes the live map ONLY after the rename succeeds.
 // Any failure (disk, capacity) leaves the previous live map completely untouched.
 function commit(cand){
  const sh=shrink(cand);
  if(!sh)return 'capacity';
  const tmp=file+'.'+process.pid+'.'+Date.now()+'.tmp';
  try{fs.writeFileSync(tmp,sh.s,{mode:0o600,flag:'wx'});fs.renameSync(tmp,file)}
  catch(e){try{fs.unlinkSync(tmp)}catch{}ok=false;return false}
  tasks=sh.map;
  return true;
 }
 function put(id,rec){
  if(!ok)return false; // a down store refuses writes - never wipes evidence while disabled
  if(!strictId(id))return false;
  const prev=tasks.get(id);
  if(prev&&FINAL.has(prev.status))return true; // final records (terminal/unknown) are never rewritten
  const now=Date.now();
  const terminal=rec.status==='done'||rec.status==='failed';
  if(!terminal&&!prev&&live(now)>=MAX_LIVE)return 'full'; // live window saturated: caller 429s; NO live tombstone is ever evicted
  const dedupExp=prev?+prev.dedupExp:(+rec.exp||now);
  const next={v:SCHEMA_V,status:rec.status,note:truncBytes(rec.note,NOTE_CAP),result:terminal?capResult(rec.result):null,
   at:prev?+prev.at:now,dedupExp,resultExp:now+RESULT_TTL_MS,terminal};
  if(!validRec(next))return false;
  const cand=new Map(tasks);cand.set(id,next);
  const pr=commit(cand);
  if(pr!==true)return pr==='capacity'?'full':false; // no commit, no in-memory change; 'full' -> caller 429s
  return true;
 }
 function transition(id,status){ // accepted -> running: the durable effect permit
  if(!ok)return false;
  if(!strictId(id))return false;
  const prev=tasks.get(id);
  if(!prev)return false; // no durable record = no permit to run
  if(FINAL.has(prev.status))return false; // terminal/unknown: an effect must NEVER (re)start
  if(prev.status===status)return true; // idempotent
  const next={...prev,status};
  if(!validRec(next))return false;
  const cand=new Map(tasks);cand.set(id,next);
  const pr=commit(cand);
  if(pr!==true)return false; // no durable running mark = no permit; live map untouched
  return true;
 }
 function get(id){
  if(!strictId(id))return null;
  const now=Date.now();for(const[k,v]of tasks)if(+v.dedupExp<=now&&+v.resultExp<=now)tasks.delete(k); // read-path prune (dead windows only)
  return tasks.get(id)||null;
 }
 return {put,transition,get,has:id=>get(id)!==null,ok:()=>ok};
}
module.exports={createLedger,capResult,RESULT_TTL_MS,RESULT_CAP,MAX_LIVE,SCHEMA_V};
