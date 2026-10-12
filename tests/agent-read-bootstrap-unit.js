// Production read-auth bootstrap transitions (src/lib/read-auth.js - the SAME module agent.js
// runs; no mimic): first mint, restart/re-enroll, outside-TTL, unrelated private reads, replay.
const assert=require('assert'),crypto=require('crypto');
const{createReadAuth}=require('../src/lib/read-auth');
const{privateKey:PRIV,publicKey:PUB}=crypto.generateKeyPairSync('ed25519'); // the sender key
const PUBKEY=PUB;
const sign=(device,method,path,query,ts,nonce)=>crypto.sign(null,Buffer.from([method,path,query,String(ts),nonce,device].join('\n'),'utf8'),PRIV).toString('hex');
const H=(device,method,path,query,ts,nonce)=>({'x-gw-read-ts':String(ts),'x-gw-read-nonce':nonce,'x-gw-read-sig':sign(device,method,path,query,ts,nonce),'x-gw-read-device':device});
const DEV='0123456789abcdef';
// a PC state machine mirroring enroll_device: pending set on EVERY accepted enroll
function mkPC(){
 let dev='',pending=null;
 return{
  enroll(id){if(!dev)dev=DEV;pending={id:String(id),device:dev,until:Date.now()+120000};return dev},
  expire(){if(pending)pending.until=0},
  auth(){return createReadAuth({senderPubKey:PUBKEY,getDeviceId:()=>dev,getPendingEnroll:()=>pending})},
 };
}
// 1) pre-enrollment: no device yet - only '-' reads pass
{const pc=mkPC(),v=pc.auth();
 assert(v('GET','/info','',H('-','GET','/info','',Date.now(),'n-00000001')),'pre-enroll: dash /info ok');
 assert(!v('GET','/info','',H(DEV,'GET','/info','',Date.now(),'n-00000002')),'pre-enroll: unknown device refused')}
// 2) first mint: exactly the pending command's /task fetch passes under '-'
{const pc=mkPC(),v=pc.auth();pc.enroll('cmd-mint-01');
 assert(v('GET','/task','id=cmd-mint-01',H('-','GET','/task','id=cmd-mint-01',Date.now(),'n-00000010')),'mint: pending /task under dash ok');
 assert(!v('GET','/info','',H('-','GET','/info','',Date.now(),'n-00000011')),'mint: /info under dash REFUSED');
 assert(!v('GET','/task','id=cmd-other-9',H('-','GET','/task','id=cmd-other-9',Date.now(),'n-00000012')),'mint: unrelated /task id under dash REFUSED');
 assert(v('GET','/info','',H(DEV,'GET','/info','',Date.now(),'n-00000013')),'mint: enrolled device /info ok');
 assert(v('GET','/task','id=cmd-other-9',H(DEV,'GET','/task','id=cmd-other-9',Date.now(),'n-00000014')),'mint: enrolled device reads any task');
 // replay protection survives the bootstrap exception
 const ts=Date.now(),h=H('-','GET','/task','id=cmd-mint-01',ts,'n-00000015');
 assert(v('GET','/task','id=cmd-mint-01',h),'bootstrap read ok');
 assert(!v('GET','/task','id=cmd-mint-01',h),'same nonce replayed - refused');
}
// 3) outside the TTL: the bootstrap window is closed
{const pc=mkPC(),v=pc.auth();pc.enroll('cmd-mint-02');pc.expire();
 assert(!v('GET','/task','id=cmd-mint-02',H('-','GET','/task','id=cmd-mint-02',Date.now(),'n-00000020')),'expired: dash refused');
 assert(v('GET','/task','id=cmd-mint-02',H(DEV,'GET','/task','id=cmd-mint-02',Date.now(),'n-00000021')),'expired: enrolled device still reads')}
// 4) restart with an EXISTING identity: no pending - dash fully closed; re-enroll re-opens exactly its command id
{const pc=mkPC();pc.enroll('cmd-before-restart');pc.expire();
 const v=pc.auth(); // restart: fresh verifier, SAME device, no live pending... enroll state persists until expiry only; simulate restart:
 // after a restart the process loses pending - rebuild a PC with the same device and NO pending
 const pc2=mkPC();pc2.enroll('__boot__');pc2.expire(); // existing identity, no pending window
 const v2=pc2.auth();
 assert(!v2('GET','/task','id=cmd-before-restart',H('-','GET','/task','id=cmd-before-restart',Date.now(),'n-00000030')),'restart: dash refused for pre-restart command');
 pc2.enroll('cmd-reenroll-01'); // the re-enroll command itself opens ITS window (already-enrolled path)
 assert(v2('GET','/task','id=cmd-reenroll-01',H('-','GET','/task','id=cmd-reenroll-01',Date.now(),'n-00000031')),'re-enroll: its own terminal fetch passes under dash');
 assert(!v2('GET','/info','',H('-','GET','/info','',Date.now(),'n-00000032')),'re-enroll: /info still refused under dash');
}
// 5) wrong enrolled device never reads
{const pc=mkPC(),v=pc.auth();pc.enroll('cmd-mint-03');
 assert(!v('GET','/task','id=cmd-mint-03',H('fedcba9876543210','GET','/task','id=cmd-mint-03',Date.now(),'n-00000040')),'foreign device refused')}
console.log('AGENT-READ-BOOTSTRAP-UNIT: PASS');
