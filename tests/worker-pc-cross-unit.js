// Cross tests: worker/outbound-sign.js output verified by the REAL PC-side verifier
// (server/lib/verify.js - the same code the standalone server runs). No re-implemented formulas.
const assert=require('assert'),crypto=require('crypto');
const{signReadRequest,buildCommandEnvelope,CMD_TTL_MS}=require('../worker/outbound-sign.js');
const{createVerifier}=require('../server/lib/verify.js');
const{signerId,KINDS}=require('../src/lib/command-contract.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const PUB_B64=PUB.export({format:'der',type:'spki'}).toString('base64');
const PRIV_B64=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
const env={GW_SIGN_PRIVATE:PRIV_B64};
const DEV=crypto.createHash('sha256').update('devpub').digest('hex').slice(0,16);
const V=createVerifier({deviceId:DEV,senderPubB64:PUB_B64});
const hdr=r=>({'x-gw-read-ts':String(r.ts),'x-gw-read-nonce':r.nonce,'x-gw-read-device':r.device,'x-gw-read-sig':r.sig});
(async()=>{
 // read: signed request passes the REAL verifyReadAuth
 const r=await signReadRequest(env,{device:DEV,method:'GET',path:'/task',query:'id=cmd-0001'});
 assert(V.verifyReadAuth('GET','/task','id=cmd-0001',hdr(r))===true,'real verifier accepts the signed read');
 assert(V.verifyReadAuth('GET','/task','id=cmd-0001',hdr(r))===false,'nonce replay refused');
 assert(V.verifyReadAuth('GET','/info','',hdr(r))===false,'path mismatch refused');
 const r2=await signReadRequest(env,{device:DEV,path:'/info',query:''});
 assert(V.verifyReadAuth('GET','/info','',hdr(r2))===true,'/info empty query accepted');
 const V2=createVerifier({deviceId:'f'.repeat(16),senderPubB64:PUB_B64});
 assert(V2.verifyReadAuth('GET','/task','id=cmd-0001',hdr(await signReadRequest(env,{device:DEV,path:'/task',query:'id=cmd-0001'})))===false,'device mismatch refused');
 // read signer hardening
 await assert.rejects(()=>signReadRequest(env,{device:DEV,method:'POST',path:'/task',query:'id=cmd-0001'}),'POST refused');
 await assert.rejects(()=>signReadRequest(env,{device:DEV,path:'/cmd',query:''}),'arbitrary path refused');
 await assert.rejects(()=>signReadRequest(env,{device:DEV,path:'/task',query:'id=a&id=b'}),'duplicate param refused');
 await assert.rejects(()=>signReadRequest(env,{device:DEV,path:'/task',query:'id=__proto__'}),'prototype id refused');
 await assert.rejects(()=>signReadRequest(env,{device:DEV,path:'/task',query:'x='+('y'.repeat(300))}),'overlong query refused');
 // v2 envelope: passes the REAL validEnvelope with device binding; v1 passes as legacy
 const data={query:'dad'};
 const e2=await buildCommandEnvelope(env,{id:'cmd-0001',kind:'find_files',device:DEV,data});
 assert(V.validEnvelope(e2,JSON.stringify(e2.data))===true,'v2 envelope verified by the real validEnvelope');
 assert(V.validEnvelope({...e2,device:'f'.repeat(16)},JSON.stringify(e2.data))===false,'device field is inside the signature - tampering breaks it (the match refusal itself is onCommand wrong_device)');
 assert(V.validEnvelope(e2,JSON.stringify({query:'mom'}))===false,'payload tamper fails');
 const e1=await buildCommandEnvelope(env,{id:'cmd-0002',kind:'find_files',data});
 assert(V.validEnvelope(e1,JSON.stringify(e1.data))===true,'v1 legacy envelope verified');
 // shared contract: signer refuses what the ledger/PC would refuse
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'constructor',kind:'find_files',data}),'prototype id refused at signing');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0003',kind:'not_a_kind',data}),'unknown kind refused at signing');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0004',kind:'find_files',data:{id:'override'}}),'reserved field refused at signing');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0005',kind:'find_files',data,ttlMs:1000.5}),'fractional ttl refused');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0006',kind:'find_files',data,ttlMs:NaN}),'NaN ttl refused');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0007',kind:'find_files',data,ttlMs:Infinity}),'Infinite ttl refused');
 // declared subset: UUID and ULID shapes fit the signer contract AND the ledger shape
 const uuid=crypto.randomUUID();
 assert(signerId(uuid),'UUID fits the signer subset: '+uuid);
 assert(signerId('01J9ZQ7W6E8K0M2N4P6R8T0V1A'),'ULID fits the signer subset');
 assert(!signerId('short'),'short id refused');
 assert(KINDS.has('find_files')&&KINDS.has('read_file')&&!KINDS.has('exec'),'kind allowlist closed');
 const e5=await buildCommandEnvelope(env,{id:uuid,kind:'find_files',device:DEV,data,ttlMs:1000});
 assert(e5.exp-e5.ts===1000&&Number.isInteger(e5.exp),'integer ttl honored');
 console.log('WORKER-PC-CROSS-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
