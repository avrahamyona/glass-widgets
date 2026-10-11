// A5: sender client - turns a user intent into a signed command envelope, POSTs it to the
// worker with X-GW-Reply-Key, and polls /task for the terminal status. LOCAL component:
// the live command-intake route is not wired yet, so every call goes through an injected
// fetch; tests run fully offline.
// Contract (docs/sender-tunnel-contract.md + worker-integration-plan A5):
//  - id under the EXISTING strict id contract (crypto.randomUUID fits SIGNER_ID_RE) - no new scheme.
//  - kind from the closed allowlist, data a plain object, ts/exp + Ed25519 signature via
//    worker/outbound-sign.js (the same builder the worker route uses).
//  - Idempotent retry: SAME id + SAME payload. A 409 duplicate returns the cached outcome -
//    never a new id. done/unknown are NOT authorization to re-execute.
//  - The reply key is a private sender credential: header only, never in the URL or logs.
const crypto=require('crypto');
const{buildCommandEnvelope,signReadRequest,CMD_TTL_MS}=require('../../worker/outbound-sign');
const{assertKind}=require('../../src/lib/command-contract');
const CMD_PATH='/glasswidgets/agent/command'; // intake route not wired live yet; overridable per call
const TERMINAL=new Set(['done','failed','unknown']); // ledger terminal states; 'unknown' = reconcile manually, never re-run

function createSenderClient({workerUrl,replyKey,signPrivate,device,fetchImpl,pollIntervalMs=2000,pollTimeoutMs=120000}){
 if(!workerUrl||!replyKey||!signPrivate)throw new Error('sender client needs workerUrl, replyKey and signPrivate');
 if(typeof fetchImpl!=='function')throw new Error('fetchImpl required (injected - no implicit network)'); // never a hidden global fetch
 const env={GW_SIGN_PRIVATE:signPrivate};
 const base=String(workerUrl).replace(/\/+$/,'');

 // Build + sign + POST one command. Pass an explicit id for idempotent retries; without one a
 // fresh UUID is minted and returned so the caller can persist it for the retry.
 async function sendCommand({id,kind,data,ttlMs,device:dev,path}){
  assertKind(kind); // closed allowlist before ANY network use
  const cmdId=id||crypto.randomUUID();
  const env2=await buildCommandEnvelope(env,{id:cmdId,kind,device:dev||device,data,ttlMs});
  if(Date.now()>=env2.exp)throw new Error('refusing to send an already-expired envelope'); // expired = refused, no effect
  const r=await fetchImpl(base+(path||CMD_PATH),{method:'POST',headers:{'content-type':'application/json','X-GW-Reply-Key':replyKey},body:JSON.stringify(env2)});
  if(r.status===202)return {id:cmdId,status:'accepted',envelope:env2};
  if(r.status===409){const b=await r.json().catch(()=>({}));return {id:cmdId,status:'duplicate',outcome:b&&b.outcome!=null?b.outcome:b,envelope:env2};} // cached outcome - never re-execute
  const text=await r.text().catch(()=>'');
  throw new Error('worker refused command: '+r.status+' '+text.slice(0,200));
 }

 // Signed read of /task?id=... - six-field read canonical exactly as the handler verifies it.
 async function pollTask(id,{device:dev}={}){
  const query='id='+encodeURIComponent(String(id));
  const rd=await signReadRequest(env,{device:dev||device,method:'GET',path:'/task',query});
  const u=base+'/task?'+query+'&ts='+rd.ts+'&nonce='+rd.nonce+'&device='+encodeURIComponent(rd.device)+'&sig='+rd.sig;
  const r=await fetchImpl(u,{method:'GET'});
  if(r.status!==200)throw new Error('task poll refused: '+r.status);
  return r.json();
 }

 // Poll until a terminal state (done/failed/unknown) or timeout. 'unknown' is returned, not
 // retried - exactly-once across crashes is NOT claimed, it needs manual reconciliation.
 async function waitTerminal(id,{device:dev,intervalMs,timeoutMs}={}){
  const t0=Date.now(),iv=intervalMs==null?pollIntervalMs:intervalMs,to=timeoutMs==null?pollTimeoutMs:timeoutMs; // ==null: an explicit 0 timeout is honored, never silently widened
  for(;;){
   const t=await pollTask(id,{device:dev});
   if(t&&TERMINAL.has(t.status))return t;
   if(Date.now()-t0>=to)return {id:String(id),status:'timeout',last:t};
   await new Promise(res=>setTimeout(res,iv));
  }
 }
 return {sendCommand,pollTask,waitTerminal,CMD_PATH,CMD_TTL_MS};
}
module.exports={createSenderClient,TERMINAL};
