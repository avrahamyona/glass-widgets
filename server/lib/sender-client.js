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
const{buildCommandEnvelope,signReadRequest,CMD_TTL_MS,DATA_BYTES_CAP}=require('../../worker/outbound-sign');
const{assertKind,assertTtl,strictId}=require('../../src/lib/command-contract');
const CMD_PATH='/cmd'; // real local-server intake (worker proxy path TBD - not wired)
const TASK_PATH='/task';
const TERMINAL=new Set(['done','failed','unknown']); // 'unknown' = reconcile manually, never re-run
const BODY_CAP=262144; // max response body BYTES (stream-bounded, not post-hoc)
const HEALTH_TTL_MS=300000; // device identity proof is re-fetched after this - never cached forever
const sha256=s=>crypto.createHash('sha256').update(s,'utf8').digest('hex');
const TIMER_MAX=2**31-1; // above this setTimeout overflows to ~1ms
const finiteMs=(v,d)=>{v=+v;return Number.isFinite(v)&&v>=0?Math.min(TIMER_MAX,Math.floor(v)):d}; // timeouts: finite integers, bounded BOTH ways

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
function envelopeSchemaOk(e,expectDevice){ // expectDevice null/undefined = preEnroll bootstrap: the envelope must carry NO device (v1)
 try{
  if(!e||typeof e!=='object'||Array.isArray(e))return false;
  if(!strictId(e.id)||!e.kind||!Number.isFinite(e.ts)||!Number.isFinite(e.exp))return false;
  assertKind(e.kind);
  if(!/^[0-9a-f]{128}$/.test(String(e.sig||'')))return false; // shape only - authenticity is the PC's to verify
  if(expectDevice==null){if(e.device!=null)return false}else if(String(e.device||'')!==String(expectDevice))return false; // v2 device binding REQUIRED post-enrollment; NO device pre-enrollment
  if(!Number.isInteger(e.ts)||!Number.isInteger(e.exp))return false; // integer timestamps, like the builder emits
  if(!(e.exp>e.ts))return false;
  try{assertTtl(e.exp-e.ts)}catch{return false} // the SHARED TTL contract (1000..300000 ms) - never a narrower private cap
  if(e.data==null||typeof e.data!=='object'||Array.isArray(e.data))return false;
  if(Buffer.byteLength(JSON.stringify(e.data),'utf8')>DATA_BYTES_CAP)return false; // same bound the builder enforces
  return true;
 }catch{return false}
}

// NOTE: deviceUrl/controlUrl are IMMUTABLE for the life of the client. A tunnel pointer / URL
// change REQUIRES constructing a new client (resetIdentity only clears the cached health proof -
// it never re-origins an existing client).
function createSenderClient({deviceUrl,controlUrl,replyKey,cmdKey,signPrivate,device,devicePub,fetchImpl,outbox,cmdPath,allowTextTransport=false,preEnroll=false,requestTimeoutMs=15000,pollIntervalMs=2000,pollTimeoutMs=120000,healthTtlMs=HEALTH_TTL_MS,nowFn}){
 if(!deviceUrl||!cmdKey||!signPrivate)throw new Error('sender client needs deviceUrl, cmdKey and signPrivate');
 if(typeof fetchImpl!=='function')throw new Error('fetchImpl required (injected - no implicit network)');
 // preEnroll is the ENROLLMENT BOOTSTRAP ONLY: no device key exists yet, so no health proof or
 // device-pinned status is possible. In this mode the client carries enroll_device ONLY and never
 // marks anything trusted - the challenge proof (orchestrator) is the binding.
 if(preEnroll&&devicePub)throw new Error('preEnroll mode must not pin a devicePub - none exists yet');
 if(!devicePub&&!preEnroll)throw new Error('devicePub required (registry-verified device pubkey) - an unproven status is never terminal');
 if(replyKey&&!controlUrl)throw new Error('replyKey without a controlUrl refused - a private sender credential must have NO path to the device origin'); // secret routing, fail closed
 if(controlUrl&&!replyKey)throw new Error('controlUrl requires replyKey');
 const devPub=devicePub?crypto.createPublicKey({key:Buffer.from(String(devicePub),'base64'),format:'der',type:'spki'}):null; // null in preEnroll bootstrap ONLY
 const base=strictBase(deviceUrl,'deviceUrl'),cbase=controlUrl?strictBase(controlUrl,'controlUrl'):null;
 if(cbase&&cbase===base)throw new Error('controlUrl must be a DISTINCT origin from deviceUrl - the reply key must have no path to the device origin'); // round-8 repro: identical origins passed silently
 const cpath=String(cmdPath||CMD_PATH);
 if(!/^\/[A-Za-z0-9/_-]*$/.test(cpath)||cpath.includes('..'))throw new Error('bad command path: fixed segments only');
 const env={GW_SIGN_PRIVATE:signPrivate};
 if(!outbox||typeof outbox.get!=='function'||typeof outbox.put!=='function')throw new Error('durable outbox required ({get(id),put(id,record)->true})');
 const now=typeof nowFn==='function'?nowFn:()=>Date.now();
 // allowTextTransport is TEST-ONLY: permits text()-only transports (inherently post-allocation)
 requestTimeoutMs=finiteMs(requestTimeoutMs,15000);pollIntervalMs=finiteMs(pollIntervalMs,2000);pollTimeoutMs=finiteMs(pollTimeoutMs,120000);healthTtlMs=finiteMs(healthTtlMs,HEALTH_TTL_MS);

 // one fully-raced request: the fetch itself AND a stream-bounded body read are both inside the
 // deadline, timers always cleaned up. A fetchImpl that ignores the signal still times out.
 async function req(u,opt,budgetMs){
  const budget=Math.max(1,finiteMs(Math.min(requestTimeoutMs,budgetMs==null?requestTimeoutMs:budgetMs),requestTimeoutMs));
  const ac=new AbortController();
  let timer=null,cancelBody=null,settled=false;
  const cancelNow=()=>{try{ac.abort()}catch{};const cb=cancelBody;cancelBody=null;if(cb)Promise.resolve().then(()=>cb()).catch(()=>{})}; // fire-and-forget: never await a cancel inside deadline cleanup
  const discardLate=r=>{ // a response that resolves AFTER the deadline gets NO reader of its own: cancel + release immediately
   try{
    if(r.body&&typeof r.body.getReader==='function'){const rd=r.body.getReader();Promise.resolve(rd.cancel()).catch(()=>{});try{rd.releaseLock()}catch{}}
    else if(r.body&&Symbol.asyncIterator in Object(r.body)){const it=r.body[Symbol.asyncIterator]();Promise.resolve().then(()=>it.return?it.return():undefined).catch(()=>{})} // return() DIRECTLY - never next() first (a hung next would never see the return, and pulling a chunk after the deadline is unwanted)
   }catch{}};
  const work=(async()=>{
   let r;
   try{
    r=await fetchImpl(u,{...opt,signal:ac.signal,redirect:'error'});
    if(settled){discardLate(r);throw new Error('request timeout');} // late resolution: no untracked body reader
    if(r.status>=300&&r.status<400)throw new Error('redirect refused - credentials never follow a redirect');
    let raw;
    const fire=fn=>{Promise.resolve().then(()=>fn()).catch(()=>{})}; // fire-and-forget cancel - never awaited inside an error path
    const readIt=async(next,cancel)=>{
     const chunks=[];let n=0;
     for(;;){const{done,value}=await next();
      if(settled){fire(cancel);throw new Error('request timeout')}
      if(done)break;n+=value.length;
      if(n>BODY_CAP){try{ac.abort()}catch{};fire(cancel);throw new Error('response body over cap')} // synchronous abort FIRST - a cancel that never resolves must not delay it
      chunks.push(value)}
     return Buffer.concat(chunks.map(c=>Buffer.isBuffer(c)?c:Buffer.from(c))).toString('utf8')};
    if(r.body&&typeof r.body.getReader==='function'){
     const rd=r.body.getReader();cancelBody=async()=>{try{await rd.cancel()}catch{}try{rd.releaseLock()}catch{}};
     let failed=true;
     try{raw=await readIt(()=>rd.read(),()=>rd.cancel());failed=false}
     finally{const cb=cancelBody;cancelBody=null;if(failed&&cb)fire(cb);try{rd.releaseLock()}catch{}} // the captured reader is cancelled on EVERY exceptional exit, BEFORE the slot is cleared
    }else if(r.body&&Symbol.asyncIterator in Object(r.body)){
     const it=r.body[Symbol.asyncIterator]();cancelBody=async()=>{try{await it.return()}catch{}};
     let failed=true;
     try{raw=await readIt(()=>it.next(),()=>it.return());failed=false}
     finally{const cb=cancelBody;cancelBody=null;if(failed&&cb)fire(cb)}
    }else if(typeof r.text==='function'){
     if(!allowTextTransport)throw new Error('unbounded transport (text-only body): a stream body is required outside tests');
     raw=await r.text();
     if(Buffer.byteLength(raw,'utf8')>BODY_CAP)throw new Error('response body over cap');
    }else raw=String(r.body||'');
    if(Buffer.byteLength(raw,'utf8')>BODY_CAP)throw new Error('response body over cap'); // utf8 BYTES, not chars
    return {status:r.status,headers:r.headers||{},rawBody:raw};
   }catch(e){cancelNow();throw e} // EVERY error path aborts the request and cancels any live body
  })();
  try{return await Promise.race([work,new Promise((_,rej)=>{timer=setTimeout(()=>{settled=true;cancelNow();rej(new Error('request timeout'))},budget)})])}
  finally{settled=true;if(timer)clearTimeout(timer);cancelBody=null}
 }
  const parseJson=r=>{try{return JSON.parse(r.rawBody)}catch{return null}};

 // health nonce proof with TTL + explicit reset on pointer change (no stale identity reuse)
 let healthAt=0;
 async function ensureDevice(budgetMs){
  if(!devPub)return false; // preEnroll bootstrap: no device key exists to prove yet
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
   if(!envelopeSchemaOk(prior.envelope,device))return {error:'outbox_record_corrupt',id:cmdId};
   const h=sha256(JSON.stringify({kind:prior.envelope.kind,data:prior.envelope.data,device:prior.envelope.device||null}));
   const h2=sha256(JSON.stringify({kind:String(kind),data:data&&typeof data==='object'?JSON.parse(JSON.stringify(data)):data,device:String(device)}));
   if(h!==h2)throw new Error('id reuse with different content refused - a retry resends the EXACT stored envelope');
   return {id:cmdId,reused:true};
  }
  const envelope=await buildCommandEnvelope(env,{id:cmdId,kind,device:device==null?undefined:String(device),data,ttlMs}); // single-device: no override (preEnroll = v1, no device field yet)
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
  if(!rec||!envelopeSchemaOk(rec.envelope,device))return {id,status:'unknown',reason:'no_valid_durable_envelope',trusted:false};
  const envelope=rec.envelope;
  if(String(envelope.id)!==id)return {id,status:'unknown',reason:'envelope_id_mismatch',trusted:false}; // the stored envelope must be FOR this id
  if(now()>=envelope.exp)return {id,status:'expired',trusted:false};
  if(preEnroll){
   if(envelope.kind!=='enroll_device')return {id,status:'refused',reason:'preEnroll carries enroll_device ONLY',trusted:false}; // bootstrap: exactly one kind, ever
  }else if(!await ensureDevice(requestTimeoutMs))return {id,status:'unknown',reason:'device_unproven',trusted:false}; // health nonce proof BEFORE payload (skipped in preEnroll: no key exists yet)
  if(now()>=envelope.exp)return {id,status:'expired',trusted:false}; // re-checked AFTER the health proof, immediately before the wire (round-8 repro)
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
  const rd=await signReadRequest(env,{device:device==null?'-':String(device),method:'GET',path:TASK_PATH,query}); // '-' addresses a not-yet-enrolled device (preEnroll reads)
  let r;
  try{r=await req(base+TASK_PATH+'?'+query,{method:'GET',headers:{'X-GW-Key':cmdKey,'X-GW-Read-Ts':String(rd.ts),'X-GW-Read-Nonce':rd.nonce,'X-GW-Read-Sig':rd.sig,'X-GW-Read-Device':rd.device}},budgetMs)} // public key + signed-read headers only
  catch(e){return {id:String(id),status:'unknown',reason:'network',trusted:false};}
  if(r.status===404)return {id:String(id),status:'unknown',reason:'not_found',trusted:false};
  if(r.status!==200)return {id:String(id),status:'unknown',reason:'refused_'+r.status,trusted:false};
  const proven=devPub?verifyDeviceSig(devPub,device,{headers:r.headers,method:'GET',path:TASK_PATH,query,reqTs:rd.ts,reqNonce:rd.nonce,status:r.status,rawBody:r.rawBody}):false; // preEnroll: nothing is ever client-trusted
  const b=parseJson(r);
  if(!b||typeof b!=='object')return {id:String(id),status:'unknown',reason:'bad_body',trusted:false};
  return {...b,id:String(id),trusted:proven}; // status without a valid device sig is INFORMATIONAL ONLY
 }

 async function waitTerminal(id,{intervalMs,timeoutMs}={}){
  const t0=now(),iv=intervalMs==null?pollIntervalMs:finiteMs(intervalMs,pollIntervalMs),to=timeoutMs==null?pollTimeoutMs:finiteMs(timeoutMs,pollTimeoutMs);
  for(;;){
   const remain=to===0?requestTimeoutMs:Math.max(1,to-(now()-t0));
   const t=await pollTask(id,{budgetMs:remain});
   // preEnroll bootstrap: nothing is client-trusted yet - the challenge proof downstream is the
   // binding. But a TRANSIENT unknown (404 before intake lands, 503 while the device key is being
   // minted) is NOT terminal: only done/failed, or a ledger-record unknown (terminal flag), ends it.
   const isTerminal=t.trusted?TERMINAL.has(t.status):(preEnroll&&(t.status==='done'||t.status==='failed'||(t.status==='unknown'&&t.terminal===true)));
   if(isTerminal)return t;
   if(to===0||now()-t0>=to)return {id:String(id),status:'timeout',last:t,trusted:false};
   await new Promise(res=>setTimeout(res,Math.min(iv,Math.max(1,to-(now()-t0)))));
  }
 }
 // control origin (worker registry/discovery) - the ONLY place the reply key is ever attached
 const CONTROL_GET_PATHS=new Set(['/glasswidgets/agent/tunnel']); // read endpoints on the control origin
 const CONTROL_POST_PATHS=new Set(['/glasswidgets/agent/enroll']); // write endpoints on the control origin
 // the reply key goes to these allowlisted registry endpoints on the CONTROL origin ONLY - never the device
 async function controlGet(path,{device:devSel,budgetMs}={}){
  if(!cbase)throw new Error('no controlUrl configured');
  if(!CONTROL_GET_PATHS.has(String(path)))throw new Error('control path not allowlisted - the reply key goes to known registry endpoints ONLY');
  let q='';
  if(path==='/glasswidgets/agent/tunnel'){ // the live route REQUIRES ?device=<16hex> (400 otherwise)
   if(!/^[0-9a-f]{16}$/.test(String(devSel||'')))throw new Error('tunnel discovery requires device=<16 hex>');
   q='?device='+devSel;
  }
  return req(cbase+path+q,{method:'GET',headers:{'X-GW-Reply-Key':replyKey}},budgetMs);
 }
 async function controlPost(path,body,budgetMs){
  if(!cbase)throw new Error('no controlUrl configured');
  if(!CONTROL_POST_PATHS.has(String(path)))throw new Error('control path not allowlisted - the reply key goes to known registry endpoints ONLY');
  if(!body||typeof body!=='object'||Array.isArray(body))throw new Error('control body must be a plain object');
  const raw=JSON.stringify(body);
  if(Buffer.byteLength(raw,'utf8')>DATA_BYTES_CAP)throw new Error('control body over cap');
  return req(cbase+path,{method:'POST',headers:{'content-type':'application/json','X-GW-Reply-Key':replyKey},body:raw},budgetMs);
 }
 return {prepare,send,sendCommand,pollTask,waitTerminal,ensureDevice,resetIdentity,controlGet,controlPost,strictBase,verifyDeviceSig,hasPinnedDeviceKey:()=>!!devPub,CMD_PATH,CMD_TTL_MS,TERMINAL};
}
module.exports={createSenderClient,TERMINAL,verifyDeviceSig};
