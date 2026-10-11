// Signed READ auth for /task and /info (shared, Electron-free: the agent AND the tests run THIS
// code). The baked command key is PUBLIC, so private reads carry X-GW-Read-Ts/Nonce/Sig/Device:
// Ed25519 over method\npath\nquery\nts\nnonce\ndevice, ts within 60s, nonce replay-cached in
// memory until ts+120s (read-only, in-memory horizon is sufficient; documented).
// Target binding: the signed request names the device it addresses - a read captured on one
// device never authorizes another; '-' addresses a not-yet-enrolled device.
// Bootstrap exception (narrow): a preEnroll sender cannot know the fresh device id yet. Exactly
// ONE pending enroll command's terminal fetch passes with '-': path /task, query id=<the pending
// command id>, within the pending TTL, for the currently enrolled device. /info, any other /task
// id, and anything after the TTL fail closed even inside the window.
const crypto=require('crypto');
function createReadAuth({senderPubKey,getDeviceId,getPendingEnroll,skewMs=60000}){
 if(!senderPubKey)throw new Error('read auth needs the sender public key');
 const nonces=new Map();
 return function verifyReadAuth(method,pathName,query,headers){
  const devId=String(getDeviceId&&getDeviceId()||'');
  const ts=+headers['x-gw-read-ts'],nonce=String(headers['x-gw-read-nonce']||''),sig=String(headers['x-gw-read-sig']||'');
  const device=String(headers['x-gw-read-device']||'');
  if(devId){
   if(device!==devId){
    const p=getPendingEnroll&&getPendingEnroll();
    const qid=(/(?:^|&)id=([^&]+)/.exec(String(query||''))||[])[1]||'';
    if(!(device==='-'&&p&&pathName==='/task'&&Date.now()<p.until&&p.device===devId&&qid===p.id))return false;
   }
  }else if(device!=='-')return false;
  if(!Number.isFinite(ts)||Math.abs(Date.now()-ts)>skewMs)return false;
  if(!/^[A-Za-z0-9_-]{8,64}$/.test(nonce)||!/^[0-9a-f]{128}$/.test(sig))return false;
  const now=Date.now();for(const[n,x]of nonces)if(x<=now)nonces.delete(n);
  const key=String(ts)+'|'+nonce;
  if(nonces.has(key))return false; // replay
  let ok=false;
  try{ok=crypto.verify(null,Buffer.from([method,pathName,query,String(ts),nonce,device].join('\n'),'utf8'),senderPubKey,Buffer.from(sig,'hex'))}catch{ok=false}
  if(ok)nonces.set(key,ts+120000);
  return ok;
 };
}
module.exports={createReadAuth};
