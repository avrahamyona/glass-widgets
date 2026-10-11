// A5: sender client - turns a user intent into a signed command envelope, POSTs it to the worker
// with X-GW-Reply-Key, and polls /task with signed read HEADERS for a device-proven terminal status.
// LOCAL component: the live intake/proxy routes are not wired yet; every call goes through an
// injected fetch and an injected durable outbox.
// Contract (docs/sender-tunnel-contract.md + worker-integration-plan A5 + review rounds 4-5):
//  - id under the EXISTING strict id contract (UUID fits SIGNER_ID_RE). Prepared ONCE and persisted
//    with its envelope BEFORE any network use: a network failure never loses the id, a retry resends
//    the EXACT stored envelope (never a rebuild with a fresh ttl/device/payload under the same id),
//    and reusing an id with different content is refused.
//  - Reply key is a private sender credential: X-GW-Reply-Key header only, https origin only,
//    fixed paths, redirects never followed, key never in a URL.
//  - A task status is TERMINAL only with a valid device proof: the device signs
//    [id,status,ts,nonce,sha256(body)].join('\n') with its enrolled key (registry-verified pubkey).
//    Missing/bad proof, or a bare 409 cached outcome, is UNPROVEN - never a trusted completion.
//  - done/unknown are NOT authorization to re-execute; 'unknown' means manual reconciliation.
//  - Every request carries an AbortSignal deadline; waitTerminal bounds each poll AND the overall wait.
const crypto=require('crypto');
const{buildCommandEnvelope,signReadRequest,CMD_TTL_MS}=require('../../worker/outbound-sign');
const{assertKind}=require('../../src/lib/command-contract');
const CMD_PATH='/glasswidgets/agent/command'; // intake route not wired live yet; overridable per client
const TASK_PATH='/task';
const TERMINAL=new Set(['done','failed','unknown']); // 'unknown' = reconcile manually, never re-run
const sha256=s=>crypto.createHash('sha256').update(s,'utf8').digest('hex');
const canon=o=>JSON.stringify(o); // response bodies are already plain JSON from the device

function strictBase(workerUrl){
 let u;try{u=new URL(String(workerUrl))}catch{throw new Error('bad workerUrl')}
 const local=['localhost','127.0.0.1','::1'].includes(u.hostname);
 if(u.protocol!=='https:'&&!local)throw new Error('workerUrl must be https (http only for localhost tests)'); // private credentials never leave over plaintext
 if(u.username||u.password)throw new Error('credentials in workerUrl refused');
 if(u.search||u.hash)throw new Error('workerUrl must be a bare origin - no query/fragment');
 return u.origin;
}
function fixedPath(p,what){
 p=String(p||'');
 if(!/^\/[A-Za-z0-9/_-]*$/.test(p)||p.includes('..'))throw new Error('bad '+what+' path: fixed segments only, no query/fragment');
 return p;
}
// device response proof: Ed25519 over [id,status,ts,nonce,sha256(body)] with the enrolled device key
function verifyProof(devPub,id,status,proof,body){
 try{
  if(!proof||typeof proof!=='object')return false;
  const{ts,nonce,sig,bodyHash}=proof;
  if(!Number.isFinite(+ts)||Math.abs(Date.now()-+ts)>120000)return false; // fresh proof only
  if(!/^[A-Za-z0-9_-]{8,64}$/.test(String(nonce||''))||!/^[0-9a-f]{128}$/.test(String(sig||'')))return false;
  if(bodyHash!==sha256(canon(body)))return false; // proof is bound to THIS body
  return crypto.verify(null,Buffer.from([String(id),String(status),String(ts),String(nonce),String(bodyHash)].join('\n'),'utf8'),devPub,Buffer.from(String(sig),'hex'));
 }catch{return false} // any malformed proof fails CLOSED
}

function createSenderClient({workerUrl,replyKey,signPrivate,device,devicePub,fetchImpl,outbox,cmdPath,requestTimeoutMs=15000,pollIntervalMs=2000,pollTimeoutMs=120000}){
 if(!workerUrl||!replyKey||!signPrivate)throw new Error('sender client needs workerUrl, replyKey and signPrivate');
 if(typeof fetchImpl!=='function')throw new Error('fetchImpl required (injected - no implicit network)');
 if(!devicePub)throw new Error('devicePub required (registry-verified device pubkey) - an unproven status is never terminal'); // fail closed
 const devPub=crypto.createPublicKey({key:Buffer.from(String(devicePub),'base64'),format:'der',type:'spki'});
 const base=strictBase(workerUrl),cpath=fixedPath(cmdPath||CMD_PATH,'command'),tpath=fixedPath(TASK_PATH,'task');
 const env={GW_SIGN_PRIVATE:signPrivate};
 const box=outbox&&typeof outbox.get==='function'&&typeof outbox.put==='function'?outbox:null;
 if(!box)throw new Error('durable outbox required ({get(id),put(id,record)}) - an id/envelope pair must survive a crash'); // in-memory default would silently break the retry contract
 const seen=async id=>{try{return await box.get(String(id))}catch{return null}};

 async function req(u,opt){ // one bounded request: deadline + no credential-following redirects
  const ac=new AbortController();const t=setTimeout(()=>ac.abort(),requestTimeoutMs);
  try{
   const r=await fetchImpl(u,{...opt,signal:ac.signal,redirect:'error'});
   if(r.status>=300&&r.status<400)throw new Error('redirect refused - credentials never follow a redirect');
   return r;
  }finally{clearTimeout(t)}
 }

 // Build + sign + PERSIST before any network use. Same id + same content = the same stored envelope;
 // same id + different content = refused.
 async function prepare({id,kind,data,ttlMs,device:dev}){
  assertKind(kind); // closed allowlist before anything else
  const cmdId=id||crypto.randomUUID();
  const prior=await seen(cmdId);
  if(prior){
   const h=sha256(canon({kind: prior.envelope.kind,data:prior.envelope.data,device:prior.envelope.device||null}));
   const h2=sha256(canon({kind:String(kind),data:data&&typeof data==='object'?JSON.parse(JSON.stringify(data)):data,device:dev||device||null}));
   if(h!==h2)throw new Error('id reuse with different content refused - a retry resends the EXACT stored envelope');
   return {id:cmdId,envelope:prior.envelope,reused:true};
  }
  const envelope=await buildCommandEnvelope(env,{id:cmdId,kind,device:dev||device,data,ttlMs});
  await box.put(cmdId,{envelope,receipt:null,at:Date.now()}); // durable BEFORE the wire
  return {id:cmdId,envelope,reused:false};
 }

 // POST the EXACT stored envelope. A network failure returns unknown WITH the id - never a lost id.
 async function send(prep){
  const{id,envelope}=prep;
  if(Date.now()>=envelope.exp)return {id,status:'expired',trusted:false}; // expired = refused locally, no effect
  let r;
  try{r=await req(base+cpath,{method:'POST',headers:{'content-type':'application/json','X-GW-Reply-Key':replyKey},body:JSON.stringify(envelope)})}
  catch(e){return {id,status:'unknown',reason:'network',error:String(e&&e.message||e),trusted:false};} // outcome unknown - reconcile, never re-id
  if(r.status===202){await box.put(id,{envelope,receipt:{accepted:Date.now()},at:Date.now()});return {id,status:'accepted',trusted:true};}
  if(r.status===409){const b=await r.json().catch(()=>({}));const proven=b&&b.outcome&&verifyProof(devPub,id,b.outcome.status,b.outcome.proof,b.outcome.result);
   await box.put(id,{envelope,receipt:{duplicate:Date.now(),proven},at:Date.now()});
   return {id,status:'duplicate',outcome:b&&b.outcome,trusted:!!proven};} // a bare cached outcome is NOT trusted completion
  const text=await r.text().catch(()=>'');
  return {id,status:'refused',code:r.status,reason:text.slice(0,200),trusted:false};
 }
 async function sendCommand(opts){return send(await prepare(opts));}

 // Signed read of /task?id=... - the read auth rides in HEADERS (X-GW-Read-Ts/Nonce/Sig/Device),
 // exactly as the PC/server verifier expects; the URL carries only the id query.
 async function pollTask(id,{device:dev}={}){
  const query='id='+encodeURIComponent(String(id));
  const rd=await signReadRequest(env,{device:dev||device,method:'GET',path:tpath,query});
  let r;
  try{r=await req(base+tpath+'?'+query,{method:'GET',headers:{'X-GW-Read-Ts':String(rd.ts),'X-GW-Read-Nonce':rd.nonce,'X-GW-Read-Sig':rd.sig,'X-GW-Read-Device':rd.device}})}
  catch(e){return {id:String(id),status:'unknown',reason:'network',trusted:false};}
  if(r.status===404)return {id:String(id),status:'unknown',reason:'not_found',trusted:false}; // 404 is NOT execution proof
  if(r.status!==200)return {id:String(id),status:'unknown',reason:'refused_'+r.status,trusted:false};
  const b=await r.json().catch(()=>null);
  if(!b||typeof b!=='object')return {id:String(id),status:'unknown',reason:'bad_body',trusted:false};
  const proven=verifyProof(devPub,id,b.status,b.proof,b.result);
  return {...b,id:String(id),trusted:proven}; // status without a valid device proof is INFORMATIONAL ONLY
 }

 // Poll until a TRUSTED terminal state, or the overall deadline. Per-poll deadline comes from req().
 // timeoutMs:0 = exactly one poll, then return (explicit single-shot semantics, never unbounded).
 async function waitTerminal(id,{device:dev,intervalMs,timeoutMs}={}){
  const t0=Date.now(),iv=intervalMs==null?pollIntervalMs:intervalMs,to=timeoutMs==null?pollTimeoutMs:timeoutMs;
  for(;;){
   const t=await pollTask(id,{device:dev});
   if(t.trusted&&TERMINAL.has(t.status))return t; // only a device-proven terminal completes the wait
   if(to===0||Date.now()-t0>=to)return {id:String(id),status:to===0&&t.trusted?t.status:'timeout',last:t,trusted:false};
   await new Promise(res=>setTimeout(res,iv));
  }
 }
 return {prepare,send,sendCommand,pollTask,waitTerminal,strictBase,fixedPath,verifyProof,CMD_PATH,CMD_TTL_MS,TERMINAL};
}
module.exports={createSenderClient,TERMINAL,verifyProof};
