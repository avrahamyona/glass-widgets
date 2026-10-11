// A1 enrollment orchestrator (owner-backend side, docs/worker-integration-plan.md A1):
//  1. issue a one-time challenge nonce (random, episode-bound)
//  2. send enroll_device with {challenge} through the sender client (worker-signed envelope -
//     the verified PC channel) and wait for a TRUSTED (device-signed response) terminal
//  3. verify the returned challengeSig over challenge\npubkey\ndeviceId against the RETURNED
//     pubkey, and that deviceId derives from it (shared module - one canonical)
//  4. only then register at the worker registry through the CONTROL origin (reply key -
//     never the device origin)
// Safe order: the PC never receives a sender secret; a bare self-signed pubkey is never
// registered. Re-enroll of the same device resolves idempotently (already:true).
const crypto=require('crypto');
const{CHALLENGE_RE,verifyChallenge}=require('../../src/lib/enroll-challenge');
const TERMINAL_OK=new Set(['done','failed']); // 'unknown' = reconcile manually, never register
function createEnrollOrchestrator({sender}){
 if(!sender||typeof sender.sendCommand!=='function'||typeof sender.waitTerminal!=='function'||typeof sender.controlPost!=='function')
  throw new Error('enroll orchestrator needs a sender client with sendCommand/waitTerminal/controlPost');
 const senderHasPinnedKey=()=>typeof sender.hasPinnedDeviceKey==='function'?sender.hasPinnedDeviceKey():false;
 // one enrollment episode: fresh challenge -> command -> trusted terminal -> proof -> registry
 async function run({timeoutMs=120000}={}){
  const challenge=crypto.randomBytes(16).toString('base64').replace(/[+/=]/g,c=>({'+':'-','/':'_','=':''}[c])); // url-safe nonce shape
  const sent=await sender.sendCommand({kind:'enroll_device',data:{challenge},ttlMs:120000});
  if(sent.status!=='accepted')return {ok:false,stage:'send',reason:sent.reason||sent.status,id:sent.id};
  const term=await sender.waitTerminal(sent.id,{timeoutMs});
  if(!TERMINAL_OK.has(term.status))return {ok:false,stage:'proof',reason:'no terminal status',id:sent.id,last:term.status};
  // pre-enrollment the response CANNOT be device-pinned (no key existed). The binding is the
  // challenge proof below: it ties the RETURNED key to THIS episode on THIS PC. When the sender
  // carries a pinned devicePub (post-enrollment re-runs), require the trusted flag as well.
  if(term.trusted===false&&senderHasPinnedKey())return {ok:false,stage:'proof',reason:'terminal not device-proven',id:sent.id,last:term.status};
  if(term.status!=='done')return {ok:false,stage:'exec',reason:term.status,id:sent.id,note:term.note};
  const r=term.result||{};
  if(!r.pubkey||!r.deviceId||!r.challengeSig)return {ok:false,stage:'proof',reason:'missing challenge proof fields',id:sent.id};
  if(!verifyChallenge({challenge,pubkey:r.pubkey,deviceId:r.deviceId,sig:r.challengeSig}))return {ok:false,stage:'proof',reason:'challenge proof invalid',id:sent.id}; // THE binding: this PC, this episode
  let reg;try{reg=await sender.controlPost('/glasswidgets/agent/enroll',{device_id:String(r.deviceId),pubkey:String(r.pubkey)})}catch(e){return {ok:false,stage:'registry',reason:String(e&&e.message||e),id:sent.id,deviceId:r.deviceId}}
  if(reg.status===200){const b=JSON.parse(reg.rawBody||'{}');return {ok:true,id:sent.id,deviceId:r.deviceId,pubkey:r.pubkey,already:!!b.already}}
  return {ok:false,stage:'registry',reason:'registry_'+reg.status+': '+String(reg.rawBody||'').slice(0,120),id:sent.id,deviceId:r.deviceId};
 }
 return {run,CHALLENGE_RE};
}
module.exports={createEnrollOrchestrator};
