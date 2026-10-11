// Durable task-result store for the own-server leg ("החיים שלי השרתי" base): every command that
// arrives over the tunnel gets a record ('accepted' at intake, terminal status at ack), so the
// sender polls GET /task?id=... instead of relying on a relayed ack. Idempotent by design: a
// terminal record never changes, a repeated read returns it, and records live until their exp.
// Same load-bearing discipline as the replay stores: write-through tmp+rename, corrupt or
// unwritable = the store is DOWN (ok()===false) and /task answers 503 - never a pretend record.
// Telemetry-safe: records carry status/note/result metadata only; no paths, tokens or contents
// beyond what the ack already reports.
const fs=require('fs');

function createTaskStore(file,{ttlMs}={}){
 const ttl=+ttlMs||24*3600*1000;
 let ok=true;const tasks={};
 try{const j=JSON.parse(fs.readFileSync(file,'utf8'));for(const k of Object.keys(j))if(j[k]&&+j[k].exp>Date.now())tasks[k]=j[k]}
 catch(e){if(!e||e.code!=='ENOENT')ok=false} // missing file is fine; corrupt is not
 function persist(){
  const now=Date.now();
  for(const k of Object.keys(tasks))if(!(+tasks[k].exp>now))delete tasks[k];
  try{const tmp=file+'.'+process.pid+'.tmp';fs.writeFileSync(tmp,JSON.stringify(tasks),{mode:0o600,flag:'wx'});fs.renameSync(tmp,file);return true}
  catch(e){ok=false;return false}
 }
 function put(id,rec){
  const sid=String(id);if(!sid)return false;
  const prev=tasks[sid];
  if(prev&&prev.terminal)return true; // a terminal record is final - never rewritten
  const terminal=rec.status==='done'||rec.status==='failed';
  tasks[sid]={status:String(rec.status||'unknown').slice(0,20),note:String(rec.note||'').slice(0,200),result:rec.result,at:Date.now(),exp:Date.now()+ttl,terminal};
  if(!persist()){if(prev)tasks[sid]=prev;else delete tasks[sid];return false}
  return true;
 }
 return {put,get:id=>tasks[String(id)]||null,ok:()=>ok};
}
module.exports={createTaskStore};
