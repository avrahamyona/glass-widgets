// The PC-side verifiers, extracted for shared use: server/index.js consumes this factory in
// production and the cross tests drive it DIRECTLY against worker-signed envelopes - no
// re-implemented formulas in tests. Bodies are byte-identical to what server/index.js ran.
const crypto=require('crypto');
function createVerifier({deviceId,senderPubB64}){
 const signPub=crypto.createPublicKey({key:Buffer.from(senderPubB64,'base64'),format:'der',type:'spki'});
const READ_SKEW_MS=60000,readNonces=new Map();
function verifyReadAuth(method,pathName,query,headers){
 const ts=+headers['x-gw-read-ts'],nonce=String(headers['x-gw-read-nonce']||''),sig=String(headers['x-gw-read-sig']||'');
 const dev=String(headers['x-gw-read-device']||'');
 if(dev!==deviceId)return false;
 if(!Number.isFinite(ts)||Math.abs(Date.now()-ts)>READ_SKEW_MS)return false;
 if(!/^[A-Za-z0-9_-]{8,64}$/.test(nonce)||!/^[0-9a-f]{128}$/.test(sig))return false;
 const now=Date.now();for(const[n,x]of readNonces)if(x<=now)readNonces.delete(n);
 const key=String(ts)+'|'+nonce;
 if(readNonces.has(key))return false;
 let ok=false;try{ok=crypto.verify(null,Buffer.from([method,pathName,query,String(ts),nonce,dev].join('\n'),'utf8'),signPub,Buffer.from(sig,'hex'))}catch{}
 if(ok)readNonces.set(key,ts+120000);
 return ok;
}

function validEnvelope(m,payload){
 const sig=String(m.sig||'');if(!/^[0-9a-f]{128}$/.test(sig))return false;
 const ts=+m.ts,exp=+m.exp,now=Date.now();
 if(!Number.isFinite(ts)||!Number.isFinite(exp))return false;
 if(ts>now+60000||exp<=ts||exp-ts>300000||exp<=now)return false;
 const fields=m.device!=null?[String(m.device),String(m.id),String(m.kind),String(ts),String(exp),payload]:[String(m.id),String(m.kind),String(ts),String(exp),payload];
 try{return crypto.verify(null,Buffer.from(fields.join('\n'),'utf8'),signPub,Buffer.from(sig,'hex'))}catch{return false}
}

 return {verifyReadAuth,validEnvelope};
}
module.exports={createVerifier};
