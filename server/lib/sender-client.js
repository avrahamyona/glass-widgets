// A5: sender client - turns a user intent into a signed command envelope, POSTs it, and polls
// /task for a device-PROVEN terminal status. LOCAL component: the worker proxy route is not wired
// yet, so the client talks the REAL local-server contract (src/lib/localserver.js) end to end:
//  - Every request carries X-GW-Key (the command key). Reads additionally carry the signed-read
//    headers X-GW-Read-Ts/Nonce/Sig/Device (six-field read canonical, verified by the PC).
//  - Before ANY command payload, a health proof: GET /health?nonce=<fresh> and verify the response
//    sig over deviceId+'\n'+nonce with the registry-verified device pubkey (fail closed).
//  - A task status is TERMINAL only with a valid X-GW-Device-Sig over the request-bound canonical
//    [deviceId, method, path, query, REQUEST ts, REQUEST nonce, HTTP status, sha256(exact raw body)]
//    (docs/sender-tunnel-contract.md). The proof is bound to THIS request's nonce - no replay.
//  - Durable outbox BEFORE any network use: retry resends the EXACT stored envelope; same id with
//    different content refused; outbox read failure PAUSES (never rebuild); a put that fails or
//    returns false blocks the network; send always loads the stored record by id.
//  - https origin only (http solely for localhost tests), root path only, redirects refused.
//  - AbortSignal deadline covers headers AND body (bounded body bytes); waitTerminal passes the
//    remaining overall budget into each poll. timeoutMs:0 = exactly one poll (explicit).
const crypto=require('crypto');
const{buildCommandEnvelope,signReadRequest,CMD_TTL_MS}=require('../../worker/outbound-sign');
const{assertKind}=require('../../src/lib/command-contract');
const CMD_PATH='/cmd'; // the real local-server intake path (worker proxy path TBD - not wired)
const TASK_PATH='/task';
const TERMINAL=new Set(['done','failed','unknown']); // 'unknown' = reconcile manually, never re-run
const BODY_CAP=262144; // bounded response body read
const sha256=s=>crypto.createHash('sha256').update(s,'utf8').digest('hex');

function strictBase(workerUrl){
 let u;try{u=new URL(String(workerUrl))}catch{throw new Error('bad workerUrl')}
 const local=['localhost','127.0.0.1','::1'].includes(u.hostname);
 if(u.protocol!=='https:'&&!(u.protocol==='http:'&&local))throw new Error('workerUrl must be https (http only for localhost tests)'); // explicit: ws/ftp/file never accepted, localhost does not widen protocols
 if(u.username||u.password)throw new Error('credentials in workerUrl refused');
 if(u.search||u.hash)throw new Error('workerUrl must be a bare origin - no query/fragment');
 if(u.pathname!=='/')throw new Error('workerUrl must be a ROOT origin - a path would be silently dropped'); // no silent path loss
 return u.origin;
}
// device response proof per the reviewed canonical: X-GW-Device + X-GW-Device-Sig over
// [deviceId, method, path, query, REQUEST read ts, REQUEST read nonce, HTTP status, sha256(exact raw body)]
function verifyDeviceSig(devPub,expectDevice,{headers,method,path,query,reqTs,reqNonce,status,rawBody}){
 try{
  const dev=String(headers['x-gw-device']||''),sig=String(headers['x-gw-device-sig']||'');
  if(!dev||dev!==String(expectDevice))return false; // bound to THIS device
  if(!/^[0-9a-f]{128}$/.test(sig))return false;
  const bh=sha256(rawBody); // the EXACT raw body - never a re-serialization
  const canon=[dev,method,path,query,String(reqTs),String(reqNonce),String(status),bh].join('\n');
  return crypto.verify(null,Buffer.from(canon,'utf8'),devPub,Buffer.from(sig,'hex'));
 }catch{return false} // malformed proof fails CLOSED
}

function createSenderClient({workerUrl,replyKey,cmdKey,signPrivate,device,devicePub,fetchImpl,outbox,cmdPath,requestTimeoutMs=15000,pollIntervalMs=2000,pollTimeoutMs=120000}){
 if(!workerUrl||!replyKey||!signPrivate||!cmdKey)throw new Error('sender client needs workerUrl, replyKey, cmdKey and signPrivate'); // X-GW-Key is required by the real server on EVERY request
 if(typeof fetchImpl!=='function')throw new Error('fetchImpl required (injected - no implicit network)');
 if(!devicePub)throw new Error('devicePub required (registry-verified device pubkey) - an unproven status is never terminal');
 const devPub=crypto.createPublicKey({key:Buffer.from(String(devicePub),'base64'),format:'der',type:'spki'});
 const base=strictBase(workerUrl),cpath=String(cmdPath||CMD_PATH);
 if(!/^\/[A-Za-z0-9/_-]*$/.test(cpath)||cpath.includes('..'))throw new Error('bad command path: fixed segments only');
 const env={GW_SIGN_PRIVATE:signPrivate};
 if(!outbox||typeof outbox.get!=='function'||typeof outbox.put!=='function')throw new Error('durable outbox required ({get(id),put(id,record)->true}) - an id/envelope pair must survive a crash');

 // one bounded request: AbortSignal covers headers AND body; body bytes capped; redirects refused
 async function req(u,opt,budgetMs){
  const ac=new AbortController();const deadline=Date.now()+Math.max(1,Math.min(requestTimeoutMs,budgetMs==null?requestTimeoutMs:budgetMs));
  const t=setTimeout(()=>ac.abort(),deadline-Date.now());
  try{
   const r=await fetchImpl(u,{...opt,signal:ac.signal,redirect:'error'});
   if(r.status>=300&&r.status<400)throw new Error('redirect refused - credentials never follow a redirect');
   let bodyText='';
   if(typeof r.text==='function'){const tr=r.text();bodyText=await Promise.race([tr,new Promise((_,rej)=>setTimeout(()=>rej(new Error('body read timeout')),Math.max(1,deadline-Date.now())))])}
   else bodyText=String(r.body||'');
   if(bodyText.length>BODY_CAP)throw new Error('response body over cap');
   return {status:r.status,headers:r.headers||{},bodyText};
  }finally{clearTimeout(t)} // the timer dies only AFTER the body is fully read
 }
 const json=r=>{try{return JSON.parse(r.bodyText)}catch{return null}};

 // health nonce proof: the endpoint must hold the enrolled device key BEFORE any payload flows
 let healthOk=null;
 async function ensureDevice(budgetMs){
  if(healthOk)return true;
  const nonce=crypto.randomBytes(12).toString('hex');
  let r;try{r=await req(base+'/health?nonce='+encodeURIComponent(nonce),{method:'GET',headers:{'X-GW-Key':cmdKey}},budgetMs)}catch(e){return false}
  if(r.status!==200)return false;
  const b=json(r);if(!b||b.deviceId!==String(device)||typeof b.sig!=='string')return false;
  try{healthOk=crypto.verify(null,Buffer.from(String(device)+'\n'+nonce,'utf8'),devPub,Buffer.from(b.sig,'hex'))}catch{healthOk=false}
  return healthOk;
 }

 async function prepare({id,kind,data,ttlMs,device:dev}){
  assertKind(kind);
  const cmdId=id||crypto.randomUUID();
  let prior;try{prior=await outbox.get(String(cmdId))}catch(e){return {error:'outbox_read_failed',id:cmdId};} // read failure PAUSES - never rebuild over a possibly-existing record
  if(prior){
   if(!prior.envelope)return {error:'outbox_record_corrupt',id:cmdId};
   const h=sha256(JSON.stringify({kind:prior.envelope.kind,data:prior.envelope.data,device:prior.envelope.device||null}));
   const h2=sha256(JSON.stringify({kind:String(kind),data:data&&typeof data==='object'?JSON.parse(JSON.stringify(data)):data,device:dev||device||null}));
   if(h!==h2)throw new Error('id reuse with different content refused - a retry resends the EXACT stored envelope');
   return {id:cmdId,envelope:prior.envelope,reused:true};
  }
  const envelope=await buildCommandEnvelope(env,{id:cmdId,kind,device:dev||device,data,ttlMs});
  let ok=false;try{ok=await outbox.put(cmdId,{envelope,receipt:null,at:Date.now()})===true}catch{ok=false}
  if(!ok)return {error:'outbox_commit_failed',id:cmdId}; // no durable commit = NO network
  let back=null;try{back=await outbox.get(String(cmdId))}catch{back=null} // re-read the exact stored record
  if(!back||!back.envelope||back.envelope.sig!==envelope.sig)return {error:'outbox_verify_failed',id:cmdId};
  return {id:cmdId,envelope:back.envelope,reused:false};
 }

 // send ALWAYS loads the stored record by id - an arbitrary in-memory prep never reaches the wire
 async function send(prep){
  if(prep&&prep.error)return {id:prep.id,status:'unknown',reason:prep.error,trusted:false};
  const id=String(prep&&prep.id||'');
  let rec=null;try{rec=await outbox.get(id)}catch(e){return {id,status:'unknown',reason:'outbox_read_failed',trusted:false};}
  if(!rec||!rec.envelope)return {id,status:'unknown',reason:'no_durable_envelope',trusted:false}; // fail closed
  const envelope=rec.envelope;
  if(Date.now()>=envelope.exp)return {id,status:'expired',trusted:false}; // expired = refused locally, no effect
  if(!await ensureDevice(requestTimeoutMs))return {id,status:'unknown',reason:'device_unproven',trusted:false}; // health nonce proof BEFORE payload
  let r;
  try{r=await req(base+cpath,{method:'POST',headers:{'content-type':'application/json','X-GW-Key':cmdKey,'X-GW-Reply-Key':replyKey},body:JSON.stringify(envelope)})}
  catch(e){return {id,status:'unknown',reason:'network',error:String(e&&e.message||e),trusted:false};}
  const persist=async receipt=>{try{return await outbox.put(id,{envelope,receipt,at:Date.now()})===true}catch{return false}};
  if(r.status===202){const ok=await persist({accepted:Date.now()});return ok?{id,status:'accepted',trusted:true}:{id,status:'unknown',reason:'receipt_persist_failed',trusted:false};} // never mask a network outcome behind a persist failure - report unknown WITH the id
  if(r.status===409){const proven=verifyDeviceSig(devPub,device,{headers:r.headers,method:'POST',path:cpath,query:'',reqTs:'',reqNonce:'',status:409,rawBody:r.bodyText});
   await persist({duplicate:Date.now(),proven});
   return {id,status:'duplicate',outcome:json(r),trusted:proven};} // a cached outcome without a valid device sig is NOT trusted completion
  return {id,status:'refused',code:r.status,reason:r.bodyText.slice(0,200),trusted:false};
 }
 async function sendCommand(opts){return send(await prepare(opts));}

 async function pollTask(id,{device:dev,budgetMs}={}){
  const query='id='+encodeURIComponent(String(id));
  const rd=await signReadRequest(env,{device:dev||device,method:'GET',path:TASK_PATH,query});
  let r;
  try{r=await req(base+TASK_PATH+'?'+query,{method:'GET',headers:{'X-GW-Key':cmdKey,'X-GW-Read-Ts':String(rd.ts),'X-GW-Read-Nonce':rd.nonce,'X-GW-Read-Sig':rd.sig,'X-GW-Read-Device':rd.device}},budgetMs)}
  catch(e){return {id:String(id),status:'unknown',reason:'network',trusted:false};}
  if(r.status===404)return {id:String(id),status:'unknown',reason:'not_found',trusted:false}; // 404 is NOT execution proof
  if(r.status!==200)return {id:String(id),status:'unknown',reason:'refused_'+r.status,trusted:false};
  const proven=verifyDeviceSig(devPub,dev||device,{headers:r.headers,method:'GET',path:TASK_PATH,query,reqTs:rd.ts,reqNonce:rd.nonce,status:r.status,rawBody:r.bodyText}); // bound to THIS request's ts+nonce
  const b=json(r);
  if(!b||typeof b!=='object')return {id:String(id),status:'unknown',reason:'bad_body',trusted:false};
  return {...b,id:String(id),trusted:proven}; // status without a valid device sig is INFORMATIONAL ONLY
 }

 // Poll until a TRUSTED terminal state or the overall deadline; each poll gets the REMAINING budget.
 async function waitTerminal(id,{device:dev,intervalMs,timeoutMs}={}){
  const t0=Date.now(),iv=intervalMs==null?pollIntervalMs:intervalMs,to=timeoutMs==null?pollTimeoutMs:timeoutMs;
  for(;;){
   const remain=to===0?requestTimeoutMs:Math.max(1,to-(Date.now()-t0));
   const t=await pollTask(id,{device:dev,budgetMs:remain});
   if(t.trusted&&TERMINAL.has(t.status))return t;
   if(to===0||Date.now()-t0>=to)return {id:String(id),status:'timeout',last:t,trusted:false};
   await new Promise(res=>setTimeout(res,Math.min(iv,Math.max(1,to-(Date.now()-t0))))); // the sleep never overshoots the overall budget either
  }
 }
 return {prepare,send,sendCommand,pollTask,waitTerminal,ensureDevice,strictBase,verifyDeviceSig,CMD_PATH,CMD_TTL_MS,TERMINAL};
}
module.exports={createSenderClient,TERMINAL,verifyDeviceSig};
