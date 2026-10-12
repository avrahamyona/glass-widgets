// A1 enrollment challenge binding (docs/worker-integration-plan.md A1 step 3-4): the owner
// backend issues a one-time nonce; the PC signs {challenge, pubkey, deviceId} with its device
// key. A bare self-signed pubkey proves NOTHING - only the challenge-bound signature ties the
// key to the actual PC in this enrollment episode. Shared by the PC enroll handler and the
// owner-side orchestrator: ONE canonical, ONE id-derivation rule (sha256(pubkey b64)[:16] -
// identical to the worker registry's).
const crypto=require('crypto');
const CHALLENGE_RE=/^[A-Za-z0-9_-]{8,64}$/; // one-time nonce shape (same alphabet as read nonces)
const deviceIdFromPub=pubB64=>crypto.createHash('sha256').update(String(pubB64),'utf8').digest('hex').slice(0,16);
const challengeCanonical=(challenge,pubkey,deviceId)=>[String(challenge),String(pubkey),String(deviceId)].join('\n');
const signChallenge=(deviceSign,challenge,pubkey,deviceId)=>deviceSign(challengeCanonical(challenge,pubkey,deviceId));
function verifyChallenge({challenge,pubkey,deviceId,sig}){
 try{
  if(!CHALLENGE_RE.test(String(challenge||'')))return false;
  if(deviceIdFromPub(pubkey)!==String(deviceId))return false; // the id must DERIVE from the pubkey - never self-declared
  if(!/^[0-9a-f]{128}$/.test(String(sig||'')))return false;
  const pub=crypto.createPublicKey({key:Buffer.from(String(pubkey),'base64'),format:'der',type:'spki'});
  return crypto.verify(null,Buffer.from(challengeCanonical(challenge,pubkey,deviceId),'utf8'),pub,Buffer.from(String(sig),'hex'));
 }catch{return false} // any malformed proof fails CLOSED
}
module.exports={CHALLENGE_RE,deviceIdFromPub,challengeCanonical,signChallenge,verifyChallenge};
