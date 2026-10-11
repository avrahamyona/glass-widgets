// A5: sender client against the REAL local-server contract (src/lib/localserver.js).
// SECRET ROUTING (plan A1 - the reply key must NEVER reach the PC/public tunnel):
//  - deviceUrl (direct PC/tunnel origin) gets ONLY the public X-GW-Key + signed artifacts.
//    The private X-GW-Reply-Key is accepted solely alongside a separate controlUrl (worker
//    control/discovery origin) and is attached to control-origin requests ONLY. A reply key
//    with no control origin is refused at construction - a credential without a destination
//    must not be carried.
//  - The client is single-device: no per-call device override; envelope.device always equals
//    the configured device.
// Proof + durability contract (rounds 5-7): request-bound X-GW-Device-Sig verified from
// Headers.get + the exact raw body; health nonce proof with a TTL (never cached forever,
// reset on pointer change); durable outbox BEFORE the wire with exact-envelope re-read;
// 202 is HTTP acceptance only - NOT an execution claim; only a device-signed terminal
// status completes a wait. Deadlines race the whole request (headers AND stream-bounded
// body), clamped to finite integers, timers always cleaned up.
const crypto=require('crypto');
const{buildCommandEnvelope,signReadRequest,CMD_TTL_MS}=require('../../worker/outbound-sign');
const{assertKind,strictId}=require('../../src/lib/command-contract');
const CMD_PATH='/cmd'; // real local-server intake (worker proxy path TBD - not wired)
const TASK_PATH='/task';
const TERMINAL=new Set(['done','failed','unknown']); // 'unknown' = reconcile manually, never re-run
const BODY_CAP=262144; // max response body BYTES (stream-bounded, not post-hoc)
const HEALTH_TTL_MS=300000; // device identity proof is re-fetched after this - never cached forever
const sha256=s=>crypto.createHash('sha256').update(s,'utf8').digest('hex');
const finiteMs=(v,d)=>{v=+v;return Number.isFinite(v)&&v>=0?Math.floor(v):d}; // timeouts are finite integers, clamped

function strictBase(u,what){
 let url;try{url=new URL(String(u))}catch{throw new Error('bad '+what)}
 const local=['localhost','127.0.0.1','::1'].includes(url.hostname);
 if(url.protocol!=='https:'&&!(url.protocol==='http:'&&local))throw new Error(what+' must be https (http only for localhost tests)');
 if(url.username||url.password)throw new Error('credentials in '+what+' refused');
 if(url.search||url.hash)throw new Error(what+' must be a bare origin - no query/fragment');
 if(url.pathname!=='/')throw new Error(what+' must be a ROOT origin - a path would be silently dropped');
 return url.origin;
}
// Headers-compatible getter: real fetch returns a Headers object (headers.get), the node-15
// adapter returns a plain lowercase map. Both must verify - reproduced gap from round 7.
const hget=(h,k)=>{if(!h)return '';if(typeof h.get==='function')return String(h.get(k)||'');return String(h[String(k).toLowerCase()]||'')};
// request-bound device response proof (docs/sender-tunnel-contract.md)
function verifyDeviceSig(devPub,expectDevice,{headers,method,path,query,reqTs,reqNonce,status,rawBody}){
 try{
  const dev=hget(headers,'x-gw-device'),sig=hget(headers,'x-gw-device-sig');
  if(!dev||dev!==String(expectDevice))return false;
  if(!/^[0-9a-f]{128}$/.test(sig))return false;
  const canon=[dev,method,path,query,String(reqTs),String(reqNonce),String(status),sha256(rawBody)].join('\n');
  return crypto.verify(null,Buffer.from(canon,'utf8'),devPub,Buffer.from(sig,'hex'));
 }catch{return false} // malformed proof fails CLOSED
}
// schema-check a stored envelope before it ever reaches the wire (stored bytes are trusted only after shape validation)
function envelopeSchemaOk(e){
 try{
  if(!e||typeof e!=='object'||Array.isArray(e))return false;
  if(!strictId(e.id)||!e.kind||!Number.isFinite(e.ts)||!Number.isFinite(e.exp))return false;
  assertKind(e.kind);
  if(!/^[0-9a-f]{128}$/.test(String(e.sig||'')))return false;
  if(e.data==null||typeof e.data!=='object'||Array.isArray(e.data))return false;
  return true;
 }catch{return false}
}

function createSenderClient({deviceUrl,controlUrl,replyKey,cmdKey,signPrivate,device,devicePub,fetchImpl,outbox,cmdPath,requestTimeoutMs=15000,pollIntervalMs=2000,pollTimeoutMs=120000,healthTtlMs=HEALTH_TTL_MS,nowFn}){
 if(!deviceUrl||!cmdKey||!signPrivate)throw new Error('sender client needs deviceUrl, cmdKey and signPrivate');
 if(typeof fetchImpl!=='function')throw new Error('fetchImpl required (injected - no implicit network)');
 if(!devicePub)throw new Error('devicePub required (registry-verified device pubkey) - an unproven status is never terminal');
 if(replyKey&&!controlUrl)throw new Error('replyKey without a controlUrl refused - a private sender credential must have NO path to the device origin'); // secret routing, fail closed
 if(controlUrl&&!replyKey)throw new Error('controlUrl requires replyKey');
 const devPub=crypto.createPublicKey({key:Buffer.from(String(devicePub),'base64'),format:'der',type:'spki'});
 const base=strictBase(deviceUrl,'deviceUrl'),cbase=controlUrl?strictBase(controlUrl,'controlUrl'):null;
 const cpath=String(cmdPath||CMD_PATH);
 if(!/^\/[A-Za-z0-9/_-]*$/.test(cpath)||cpath.includes('..'))throw new Error('bad command path: fixed segments only');
 const env={GW_SIGN_PRIVATE:signPrivate};
 if(!outbox||typeof outbox.get!=='function'||typeof outbox.put!=='function')throw new Error('durable outbox required ({get(id),put(id,record)->true})');
 const now=typeof nowFn==='function'?nowFn:()=>Date.now();
 requestTimeoutMs=finiteMs(requestTimeoutMs,15000);pollIntervalMs=finiteMs(pollIntervalMs,2000);pollTimeoutMs=finiteMs(pollTimeoutMs,120000);healthTtlMs=finiteMs(healthTtlMs,HEALTH_TTL_MS);

 // one fully-raced request: the fetch itself AND a stream-bounded body read are both inside the
 // deadline, timers always cleaned up. A fetchImpl that ignores the signal still times out.
 async function req(u,opt,budgetMs){
  const budget=Math.max(1,finiteMs(Math.min(requestTimeoutMs,budgetMs==null?requestTimeoutMs:budgetMs),requestTimeoutMs));
  const ac=new AbortController();
  let timer=null;
  // ONE race covers the whole request - headers AND body - so a fetchImpl that ignores the
  // abort signal, or a stream that never ends, still loses to the deadline. Timer always cleared.
  const work=(async()=>{
   const r=await fetchImpl(u,{...opt,signal:ac.signal,redirect:'error'});
   if(r.status>=300&&r.status<400)throw new Error('redirect refused - credentials never follow a redirect');
   let raw;
   if(r.body&&(typeof r.body.getReader==='function'||Symbol.asyncIterator in Object(r.body))){ // stream-bounded: stop at BODY_CAP BYTES
    const chunks=[];let n=0;
    const it=typeof r.body.getReader==='function'?async function*(){const rd=r.body.getReader();for(;;){const{done,value}=await rd.read();if(done)return;yield value}}():r.body;
    for await(const c of it){n+=c.length;if(n>BODY_CAP)throw new Error('response body over cap');chunks.push(c)}
    raw=Buffer.concat(chunks.map(c=>Buffer.isBuffer(c)?c:Buffer.from(c))).toString('utf8');
   }else if(typeof r.text==='function')raw=await r.text();
   else raw=String(r.body||'');
   if(Buffer.byteLength(raw,'utf8')>BODY_CAP)throw new Error('response body over cap'); // utf8 BYTES, not chars
   return {status:r.status,headers:r.headers||{},rawBody:raw};
  })();
  try{return await Promise.race([work,new Promise((_,rej)=>{timer=setTimeout(()=>{try{ac.abort()}catch{};rej(new Error('request timeout'))},budget)})])}
  finally{if(timer)clearTimeout(timer)}
 }
  const parseJson=r=>{try{return JSON.parse(r.rawBody)}catch{return null}};

 // health nonce proof with TTL + explicit reset on pointer change (no stale identity reuse)
 let healthAt=0;
 async function ensureDevice(budgetMs){
  if(healthAt&&now()-healthAt<healthTtlMs)return true;
  const nonce=crypto.randomBytes(12).toString('hex');
  let r;try{r=await req(base+'/health?nonce='+encodeURIComponent(nonce),{method:'GET',headers:{'X-GW-Key':cmdKey}},budgetMs)}catch(e){return false} // PUBLIC key only - never the reply key
  if(r.status!==200)return false;
  const b=parseJson(r);if(!b||b.deviceId!==String(device)||typeof b.sig!=='string')return false;
  let ok=false;try{ok=crypto.verify(null,Buffer.from(String(device)+'\n'+nonce,'utf8'),devPub,Buffer.from(b.sig,'hex'))}catch{ok=false}
  if(ok)healthAt=now();
  return ok;
 }
 const resetIdentity=()=>{healthAt=0}; // call after ANY tunnel pointer/registry change

 async function prepare({id,kind,data,ttlMs}){
  assertKind(kind);
  const cmdId=id||crypto.randomUUID();
  let prior;try{prior=await outbox.get(String(cmdId))}catch(e){return {error:'outbox_read_failed',id:cmdId};}
  if(prior){
   if(!envelopeSchemaOk(prior.envelope))return {error:'outbox_record_corrupt',id:cmdId};
   const h=sha256(JSON.stringify({kind:prior.envelope.kind,data:prior.envelope.data,device:prior.envelope.device||null}));
   const h2=sha256(JSON.stringify({kind:String(kind),data:data&&typeof data==='object'?JSON.parse(JSON.stringify(data)):data,device:String(device)}));
   if(h!==h2)throw new Error('id reuse with different content refused - a retry resends the EXACT stored envelope');
   return {id:cmdId,reused:true};
  }
  const envelope=await buildCommandEnvelope(env,{id:cmdId,kind,device:String(device),data,ttlMs}); // single-device: no override
  let ok=false;try{ok=await outbox.put(cmdId,{envelope,receipt:null,at:now()})===true}catch{ok=false}
  if(!ok)return {error:'outbox_commit_failed',id:cmdId};
  let back=null;try{back=await outbox.get(String(cmdId))}catch{back=null}
  if(!back||JSON.stringify(back.envelope)!==JSON.stringify(envelope))return {error:'outbox_verify_failed',id:cmdId}; // the EXACT serialized envelope, not just the sig
  return {id:cmdId,reused:false};
 }

 // send loads the stored record by id and validates its schema BEFORE the wire. Direct transport
 // is SECRETLESS: X-GW-Key (public) + the signed envelope - the reply key is not even in scope here.
 async function send(prep){
  if(prep&&prep.error)return {id:prep.id,status:'unknown',reason:prep.error,trusted:false};
  const id=String(prep&&prep.id||'');
  let rec=null;try{rec=await outbox.get(id)}catch(e){return {id,status:'unknown',reason:'outbox_read_failed',trusted:false};}
  if(!rec||!envelopeSchemaOk(rec.envelope))return {id,status:'unknown',reason:'no_valid_durable_envelope',trusted:false};
  const envelope=rec.envelope;
  if(envelope.device&&envelope.device!==String(device))return {id,status:'unknown',reason:'device_mismatch',trusted:false}; // never send an envelope bound to another device
  if(now()>=envelope.exp)return {id,status:'expired',trusted:false};
  if(!await ensureDevice(requestTimeoutMs))return {id,status:'unknown',reason:'device_unproven',trusted:false};
  let r;
  try{r=await req(base+cpath,{method:'POST',headers:{'content-type':'application/json','X-GW-Key':cmdKey},body:JSON.stringify(envelope)})} // NO X-GW-Reply-Key on the direct path - ever
  catch(e){return {id,status:'unknown',reason:'network',error:String(e&&e.message||e),trusted:false};}
  const persist=async receipt=>{try{return await outbox.put(id,{envelope,receipt,at:now()})===true}catch{return false}};
  if(r.status===202){const ok=await persist({accepted:now()});
   return ok?{id,status:'accepted',trusted:false,note:'HTTP acceptance only - not a device execution proof'}:{id,status:'unknown',reason:'receipt_persist_failed',trusted:false};}
  if(r.status===409){await persist({duplicate:now()});
   return {id,status:'duplicate',outcome:parseJson(r),trusted:false,note:'cached outcome - not device-signed, not trusted completion'};}
  return {id,status:'refused',code:r.status,reason:r.rawBody.slice(0,200),trusted:false};
 }
 async function sendCommand(opts){return send(await prepare(opts));}

 async function pollTask(id,{budgetMs}={}){
  const query='id='+encodeURIComponent(String(id));
  const rd=await signReadRequest(env,{device:String(device),method:'GET',path:TASK_PATH,query});
  let r;
  try{r=await req(base+TASK_PATH+'?'+query,{method:'GET',headers:{'X-GW-Key':cmdKey,'X-GW-Read-Ts':String(rd.ts),'X-GW-Read-Nonce':rd.nonce,'X-GW-Read-Sig':rd.sig,'X-GW-Read-Device':rd.device}},budgetMs)} // public key + signed-read headers only
  catch(e){return {id:String(id),status:'unknown',reason:'network',trusted:false};}
  if(r.status===404)return {id:String(id),status:'unknown',reason:'not_found',trusted:false};
  if(r.status!==200)return {id:String(id),status:'unknown',reason:'refused_'+r.status,trusted:false};
  const proven=verifyDeviceSig(devPub,device,{headers:r.headers,method:'GET',path:TASK_PATH,query,reqTs:rd.ts,reqNonce:rd.nonce,status:r.status,rawBody:r.rawBody});
  const b=parseJson(r);
  if(!b||typeof b!=='object')return {id:String(id),status:'unknown',reason:'bad_body',trusted:false};
  return {...b,id:String(id),trusted:proven}; // status without a valid device sig is INFORMATIONAL ONLY
 }

 async function waitTerminal(id,{intervalMs,timeoutMs}={}){
  const t0=now(),iv=intervalMs==null?pollIntervalMs:finiteMs(intervalMs,pollIntervalMs),to=timeoutMs==null?pollTimeoutMs:finiteMs(timeoutMs,pollTimeoutMs);
  for(;;){
   const remain=to===0?requestTimeoutMs:Math.max(1,to-(now()-t0));
   const t=await pollTask(id,{budgetMs:remain});
   if(t.trusted&&TERMINAL.has(t.status))return t;
   if(to===0||now()-t0>=to)return {id:String(id),status:'timeout',last:t,trusted:false};
   await new Promise(res=>setTimeout(res,Math.min(iv,Math.max(1,to-(now()-t0)))));
  }
 }
 // control origin (worker registry/discovery) - the ONLY place the reply key is ever attached
 async function controlGet(path,budgetMs){
  if(!cbase)throw new Error('no controlUrl configured');
  if(!/^\/[A-Za-z0-9/_-]*$/.test(path))throw new Error('bad control path');
  return req(cbase+path,{method:'GET',headers:{'X-GW-Reply-Key':replyKey}},budgetMs);
 }
 return {prepare,send,sendCommand,pollTask,waitTerminal,ensureDevice,resetIdentity,controlGet,strictBase,verifyDeviceSig,CMD_PATH,CMD_TTL_MS,TERMINAL};
}
module.exports={createSenderClient,TERMINAL,verifyDeviceSig};
