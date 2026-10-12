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
const{fingerprint}=require('../../src/lib/fingerprint'); // ONE canonical - the PC shows the SAME string locally, so the user can compare
const TERMINAL_OK=new Set(['done','failed']); // 'unknown' = reconcile manually, never register
// pairing fingerprint: short, human-comparable, derived from the enrolled pubkey. The user (or an
// ALREADY authenticated channel) confirms THIS string out-of-band before any registry mutation.
// approvePairing({deviceId, pubkey, fingerprint}) -> truthy: REQUIRED user/authenticated-channel
// approval of the pairing fingerprint BEFORE any registry write. The challenge proof alone shows
// key possession + freshness - it can NEVER show this endpoint is the user's intended PC (a
// replacement endpoint can mint its own key and sign the public nonce). Without an approval the
// orchestrator returns {ok:false, stage:'pairing', fingerprint} and touches NOTHING.
function createEnrollOrchestrator({sender,approvePairing}){
 if(!sender||typeof sender.sendCommand!=='function'||typeof sender.waitTerminal!=='function'||typeof sender.controlPost!=='function')
  throw new Error('enroll orchestrator needs a sender client with sendCommand/waitTerminal/controlPost');
 const senderHasPinnedKey=()=>typeof sender.hasPinnedDeviceKey==='function'?sender.hasPinnedDeviceKey():false;
 // one enrollment episode: fresh challenge -> command -> trusted terminal -> proof -> registry
 async function run({timeoutMs=120000}={}){
  const challenge=crypto.randomBytes(16).toString('base64').replace(/[+/=]/g,c=>({'+':'-','/':'_','=':''}[c])); // url-safe nonce shape
  const sentAt=Date.now(); // episode window anchor for the pairing-evidence approvedAt check
  const sent=await sender.sendCommand({kind:'enroll_device',data:{challenge},ttlMs:120000});
  if(sent.status!=='accepted')return {ok:false,stage:'send',reason:sent.reason||sent.status,id:sent.id};
  const term=await sender.waitTerminal(sent.id,{timeoutMs});
  if(!TERMINAL_OK.has(term.status))return {ok:false,stage:'proof',reason:'no terminal status',id:sent.id,last:term.status};
  // pre-enrollment the response CANNOT be device-pinned (no key existed). The binding is the
  // challenge proof below: it ties the RETURNED key to THIS episode on THIS PC. When the sender
  // carries a pinned devicePub (post-enrollment re-runs), require the trusted flag as well.
  if(term.trusted!==true&&senderHasPinnedKey())return {ok:false,stage:'proof',reason:'terminal not device-proven',id:sent.id,last:term.status}; // fail-closed: a MISSING trusted flag refuses too (round A1-4)
  if(term.status!=='done')return {ok:false,stage:'exec',reason:term.status,id:sent.id,note:term.note};
  const r=term.result||{};
  if(!r.pubkey||!r.deviceId||!r.challengeSig)return {ok:false,stage:'proof',reason:'missing challenge proof fields',id:sent.id};
  if(!verifyChallenge({challenge,pubkey:r.pubkey,deviceId:r.deviceId,sig:r.challengeSig}))return {ok:false,stage:'proof',reason:'challenge proof invalid',id:sent.id}; // possession + freshness of the RETURNED key
  const fp=fingerprint(r.pubkey);
  // on-PC pairing evidence: copied fields can NEVER authenticate themselves, so every field is
  // cross-checked against INDEPENDENT recomputation: the card id must be the EXACT deterministic id
  // of THIS episode (recomputed from sent.id, not prefix-matched), the fingerprint must equal
  // fp(returned pubkey), and the human-tap instant must sit inside THIS episode's measured window.
  // A FRESH sender (no pinned key) always requires this evidence; an untrusted 'already enrolled'
  // note bypasses NOTHING (dropped entirely). A PINNED sender's terminal is already device-proven
  // (trusted===true enforced above), so its re-enroll needs no fresh pairing record - but one that
  // arrives is still cross-checked.
  const expectCard='local-approve-'+crypto.createHash('sha256').update(String(sent.id),'utf8').digest('hex').slice(0,32);
  const fresh=!senderHasPinnedKey();
  let pairing=null;
  if(r.pairing&&typeof r.pairing==='object'){
   const pr=r.pairing;
   if(typeof pr.fingerprint!=='string'||pr.fingerprint!==fp||pr.cardId!==expectCard||!(+pr.approvedAt>=sentAt-10000&&+pr.approvedAt<=Date.now()+10000))
    return {ok:false,stage:'pairing',reason:'pairing evidence mismatch',id:sent.id,deviceId:r.deviceId,pubkey:r.pubkey,fingerprint:fp};
   pairing={fingerprint:pr.fingerprint,cardId:pr.cardId,approvedAt:+pr.approvedAt};
  }else if(fresh)return {ok:false,stage:'pairing',reason:'fresh mint without on-PC pairing evidence',id:sent.id,deviceId:r.deviceId,pubkey:r.pubkey,fingerprint:fp};
  if(typeof approvePairing!=='function')return {ok:false,stage:'pairing',reason:'no pairing approval channel',id:sent.id,deviceId:r.deviceId,pubkey:r.pubkey,fingerprint:fp}; // fail closed - never register unapproved
  let approved=false;try{approved=(await approvePairing({deviceId:String(r.deviceId),pubkey:String(r.pubkey),fingerprint:fp,episode:String(sent.id),challenge,pairing}))===true}catch{approved=false} // STRICT true - a truthy string/object is NOT an approval; the callback receives the episode id + challenge + the cross-checked on-PC pairing record (null on a re-enroll claim) so its decision binds to THIS enrollment and THIS key
  if(!approved)return {ok:false,stage:'pairing',reason:'pairing not approved',id:sent.id,deviceId:r.deviceId,pubkey:r.pubkey,fingerprint:fp};
  let reg;try{reg=await sender.controlPost('/glasswidgets/agent/enroll',{device_id:String(r.deviceId),pubkey:String(r.pubkey)})}catch(e){return {ok:false,stage:'registry',reason:String(e&&e.message||e),id:sent.id,deviceId:r.deviceId}}
  if(reg.status===200){
   let b=null;try{b=JSON.parse(reg.rawBody||'')}catch{return {ok:false,stage:'registry',reason:'registry bad json',id:sent.id,deviceId:r.deviceId}} // malformed success bodies refuse, never throw
   if(!b||b.ok!==true)return {ok:false,stage:'registry',reason:'registry not ok',id:sent.id,deviceId:r.deviceId};
   return {ok:true,id:sent.id,deviceId:r.deviceId,pubkey:r.pubkey,already:b.already===true}}
  return {ok:false,stage:'registry',reason:'registry_'+reg.status+': '+String(reg.rawBody||'').slice(0,120),id:sent.id,deviceId:r.deviceId};
 }
 return {run,CHALLENGE_RE,fingerprint};
}
module.exports={createEnrollOrchestrator};
