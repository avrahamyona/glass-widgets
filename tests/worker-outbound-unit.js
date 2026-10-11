// Unit tests for worker/outbound-sign.js: canonical byte-compatibility with the PC verifiers,
// id/device validation, v1/v2 shapes, ttl bounds, fail-closed env.
const assert=require('assert'),crypto=require('crypto');
const{signReadRequest,buildCommandEnvelope,CMD_TTL_MS}=require('../worker/outbound-sign.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const env={GW_SIGN_PRIVATE:PRIV.export({format:'der',type:'pkcs8'}).toString('base64')};
const pubK=()=>crypto.createPublicKey({key:Buffer.from(PUB.export({format:'der',type:'spki'}).toString('base64'),'base64'),format:'der',type:'spki'});
const DEV=crypto.createHash('sha256').update('devpub').digest('hex').slice(0,16);
const verify=(fields,sig)=>crypto.verify(null,Buffer.from(fields.join('\n'),'utf8'),pubK(),Buffer.from(sig,'hex'));
(async()=>{
 // read signer: six-field canonical exactly as verifyReadAuth expects
 const r=await signReadRequest(env,{device:DEV,method:'GET',path:'/task',query:'id=cmd-0001'});
 assert(/^[0-9a-f]{24}$/.test(r.nonce)&&/^[0-9a-f]{128}$/.test(r.sig),'read shape');
 assert(verify(['GET','/task','id=cmd-0001',String(r.ts),r.nonce,DEV],r.sig),'read canonical verifies');
 assert(!verify(['GET','/info','id=cmd-0001',String(r.ts),r.nonce,DEV],r.sig),'path is bound');
 assert(!verify(['GET','/task','id=cmd-0001',String(r.ts),r.nonce,'0'.repeat(16)],r.sig),'device is bound');
 await assert.rejects(()=>signReadRequest(env,{device:'nope',path:'/task',query:''}),'bad device refused');
 await assert.rejects(()=>signReadRequest(env,{device:DEV,path:'task',query:''}),'bad path refused');
 await assert.rejects(()=>signReadRequest({},{device:DEV,path:'/task',query:''}),'missing key fails closed');
 // v2 command: device-first six-field
 const data={query:'dad'};
 const e2=await buildCommandEnvelope(env,{id:'cmd-0001',kind:'find_files',device:DEV,data});
 assert(e2.device===DEV&&verify([DEV,'cmd-0001','find_files',String(e2.ts),String(e2.exp),JSON.stringify(data)],e2.sig),'v2 canonical verifies');
 assert(e2.exp-e2.ts===CMD_TTL_MS,'default ttl');
 assert(!verify(['cmd-0001','find_files',String(e2.ts),String(e2.exp),JSON.stringify(data)],e2.sig),'v2 sig does NOT pass the v1 canonical');
 // v1 legacy: five-field, no device key in the envelope
 const e1=await buildCommandEnvelope(env,{id:'cmd-0002',kind:'find_files',data});
 assert(!('device' in e1)&&verify(['cmd-0002','find_files',String(e1.ts),String(e1.exp),JSON.stringify(data)],e1.sig),'v1 canonical verifies');
 // payload canonicalization: data arrives as the exact JSON object sent
 const e3=await buildCommandEnvelope(env,{id:'cmd-0003',kind:'read_file',device:DEV,data:{path:'/a b/ק.txt'}});
 assert(verify([DEV,'cmd-0003','read_file',String(e3.ts),String(e3.exp),JSON.stringify(e3.data)],e3.sig),'non-ascii payload canonical');
 // validation
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'x',kind:'find_files',data}),'short id refused');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0004',kind:'find_files',device:'BAD',data}),'bad device refused');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0005',kind:'find_files',device:DEV,data,ttlMs:99999999}),'over-cap ttl refused (no silent clamp)');
 const e4=await buildCommandEnvelope(env,{id:'cmd-0006',kind:'find_files',device:DEV,data,ttlMs:300000});
 assert(e4.exp-e4.ts===300000,'max ttl honored');
 // round-3 refusals: the exact serialized object is checked, nothing slips past
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0007',kind:'find_files',device:DEV,data:{__tunnel:true}}),'__tunnel in data refused'); // ops repro: data{__tunnel:true} used to get signed then PC refused
 const spoof={toJSON(){return {id:'spoof',query:'x'}}};
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0008',kind:'find_files',device:DEV,data:spoof}),'toJSON smuggling a reserved field refused'); // toJSON()=>{id:...} passes a precheck, fails on the SERIALIZED object
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0009',kind:'find_files',device:DEV,data:['a','b']}),'array data refused, no silent {}');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0010',kind:'find_files',device:DEV,data:'just-a-string'}),'primitive data refused, no silent {}');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0011',kind:'find_files',device:DEV,data:{device:'spoof'}}),'device in data refused (shared RESERVED union)');
 // round-4: post-serialization type + caps (ops repros: toJSON returning [] / 7 / null, and Date->string)
 const mk=j=>({toJSON(){return j}});
 for(const bad of [[],7,null]) await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0012',kind:'find_files',device:DEV,data:mk(bad)}),'toJSON -> '+JSON.stringify(bad)+' refused');
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0013',kind:'find_files',device:DEV,data:{when:new Date(0)}}),'Date field refused (serializes to a string, not an object - wire would mismatch)');
 const big='x'.repeat(9000);
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0014',kind:'find_files',device:DEV,data:{q:big}}),'data over byte cap refused at the helper');
 let deep={},p=deep; for(let i=0;i<12;i++){p.n={};p=p.n}
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0015',kind:'find_files',device:DEV,data:deep}),'data over depth cap refused');
 const okNested=await buildCommandEnvelope(env,{id:'cmd-0016',kind:'find_files',device:DEV,data:{queries:['a','b','c']}}); // nested arrays are legitimate
 assert(verify([DEV,'cmd-0016','find_files',String(okNested.ts),String(okNested.exp),JSON.stringify(okNested.data)],okNested.sig),'nested array payload signs+verifies');
 const cyc={a:1};cyc.self=cyc;
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0017',kind:'find_files',device:DEV,data:cyc}),'cyclic data refused as a validation error, not a RangeError');
 const wide={};for(let i=0;i<11000;i++)wide['k'+i]=i;
 await assert.rejects(()=>buildCommandEnvelope(env,{id:'cmd-0018',kind:'find_files',device:DEV,data:wide}),'over-wide data refused by the node-count guard');
 console.log('WORKER-OUTBOUND-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
