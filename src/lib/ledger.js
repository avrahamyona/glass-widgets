// The tunnel intake ledger ("החיים שלי השרתי" base): ONE durable, transactional record per
// command, intake -> accepted -> terminal. It replaces the old two-file split (replay store +
// task store) whose crash window could block a retry at 409 with no task record.
//
// Record lifecycle (explicit, no hidden TTLs):
//   - 'accepted': written BEFORE any effect (dispatch). Expires at the envelope's own exp
//     (PENDING horizon): after that a poll returns 404 and the sender treats it as "lost, retry".
//   - 'done'/'failed' (terminal): final, never rewritten. Retained RESULT_TTL_MS (24h) for
//     idempotent polling, then pruned; a later replay of the same envelope is already 403-expired
//     at intake, so dedup never outlives its need.
//
// Discipline (same as every load-bearing store here): strict schema on load - ANY invalid record
// = store DOWN (ok()===false, intake 503, /task 503); put on a down store refuses (never wipes
// evidence); unique-tmp + rename writes; tmp cleaned on failure; bounded by MAX_RECORDS and
// MAX_BYTES (oldest evicted, non-terminal first); ids are strict-format (no prototype tricks);
// result payloads are byte-CAPPED at write (metadata-bounded, never a raw clipboard/path dump).
const fs=require('fs');

const RESULT_TTL_MS=24*3600*1000; // terminal retention
const MAX_RECORDS=200,MAX_BYTES=256*1024,RESULT_CAP=2000,NOTE_CAP=200;
const ID_RE=/^[\w-]{1,80}$/,STATUSES=new Set(['accepted','done','failed']);
const strictId=id=>typeof id==='string'&&ID_RE.test(id)&&!['__proto__','constructor','prototype'].includes(id); // no prototype tricks, ever

function validRec(r){
 return r&&typeof r==='object'&&STATUSES.has(r.status)&&typeof r.note==='string'&&r.note.length<=NOTE_CAP
  &&Number.isFinite(r.at)&&Number.isFinite(r.exp)&&typeof r.terminal==='boolean'
  &&(r.result===undefined||JSON.stringify(r.result).length<=RESULT_CAP+200);
}
function capResult(result){
 if(result===undefined)return undefined;
 let s;try{s=JSON.stringify(result)}catch{return {truncated:true,unserializable:true}}
 if(Buffer.byteLength(s)<=RESULT_CAP)return result;
 return {truncated:true,full_bytes:Buffer.byteLength(s)}; // metadata only - never the raw payload
}

function createLedger(file){
 let ok=true;const tasks=new Map(); // strict ids only, insertion-ordered
 try{const j=JSON.parse(fs.readFileSync(file,'utf8'));
  if(!j||typeof j!=='object'||Array.isArray(j))throw new Error('bad ledger');
  const now=Date.now();
  for(const k of Object.keys(j)){
   if(!strictId(k)||!validRec(j[k]))throw new Error('bad record'); // strict schema: one bad record = store down
   if(+j[k].exp>now)tasks.set(k,j[k]);
  }
 }catch(e){if(!e||e.code!=='ENOENT')ok=false} // missing file is fine; corrupt is not
 function evict(){
  while(tasks.size>MAX_RECORDS){
   let victim=null;
   for(const[k,v]of tasks)if(!v.terminal){victim=k;break}
   if(!victim)victim=tasks.keys().next().value;
   tasks.delete(victim);
  }
 }
 function persist(){
  evict();
  let s=JSON.stringify(Object.fromEntries(tasks));
  while(Buffer.byteLength(s)>MAX_BYTES&&tasks.size){ // byte cap: evict oldest until it fits
   let victim=null;for(const[k,v]of tasks)if(!v.terminal){victim=k;break}
   if(!victim)victim=tasks.keys().next().value;
   tasks.delete(victim);s=JSON.stringify(Object.fromEntries(tasks));
  }
  const tmp=file+'.'+process.pid+'.'+Date.now()+'.tmp';
  try{fs.writeFileSync(tmp,s,{mode:0o600,flag:'wx'});fs.renameSync(tmp,file);return true}
  catch(e){try{fs.unlinkSync(tmp)}catch{}ok=false;return false}
 }
 function prune(){const now=Date.now();for(const[k,v]of tasks)if(!(+v.exp>now))tasks.delete(k)}
 function put(id,rec){
  if(!ok)return false; // a down store refuses writes - never wipes evidence while disabled
  if(!strictId(id))return false;
  const prev=tasks.get(id);
  if(prev&&prev.terminal)return true; // terminal is final
  const terminal=rec.status==='done'||rec.status==='failed';
  const next={status:rec.status,note:String(rec.note||'').slice(0,NOTE_CAP),result:capResult(rec.result),
   at:Date.now(),exp:terminal?Date.now()+RESULT_TTL_MS:+rec.exp||Date.now(),terminal};
  if(!validRec(next))return false;
  tasks.set(id,next);
  if(!persist()){if(prev)tasks.set(id,prev);else tasks.delete(id);return false}
  return true;
 }
 function get(id){
  if(!strictId(id))return null;
  prune();
  return tasks.get(id)||null;
 }
 return {put,get,has:id=>get(id)!==null,ok:()=>ok};
}
module.exports={createLedger,RESULT_TTL_MS,RESULT_CAP};
