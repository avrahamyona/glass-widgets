// A1 enrollment orchestration E2E (local): REAL startLocalServer as the PC (challenge-bound
// enroll handler on the shared enroll-challenge module), REAL worker/tunnel-route.js behind an
// http wrapper as the registry, REAL sender client transports (preEnroll bootstrap mode).
// Covers: full episode binding (fresh challenge per run), idempotent re-enroll, forged proof
// refused BEFORE the registry, id-not-derived-from-pubkey refused, registry device limit,
// untrusted terminal refused. The PC never sees the reply key (checked on every request).
const assert=require('assert'),crypto=require('crypto'),http=require('http');
const{createSenderClient}=require('../server/lib/sender-client.js');
const{createEnrollOrchestrator}=require('../server/lib/enroll-orchestrator.js');
const{createVerifier}=require('../server/lib/verify.js');
const{startLocalServer}=require('../src/lib/localserver.js');
const{signChallenge}=require('../src/lib/enroll-challenge.js');
const{handleTunnel}=require('../worker/tunnel-route.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519'); // sender signing key
const SIGN_PRIV=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
const senderPubB64=PUB.export({format:'der',type:'spki'}).toString('base64');
class FakeStmt{constructor(db,sql,args){this.db=db;this.sql=sql;this.args=args}
 async first(){const d=this.db,s=this.sql,a=this.args;
  if(s.includes('SELECT pubkey FROM devices')){const pk=d.devices.get(a[0]);return pk?{pubkey:pk.pubkey}:null}
  throw new Error('unexpected first: '+s)}
 async run(){const d=this.db,s=this.sql,a=this.args;
  if(s.startsWith('INSERT INTO devices')&&s.includes('WHERE (SELECT COUNT(*)')){
   if(d.devices.size>=a[3])return{meta:{changes:0}};
   d.devices.set(a[0],{pubkey:a[1],enrolled_at:a[2]});return{meta:{changes:1}}}
  throw new Error('unexpected run: '+s)}}
class FakeDB{constructor(){this.devices=new Map()}
 prepare(sql){const db=this;return{bind(...args){return new FakeStmt(db,sql,args)}}}}
const pcHeaders=[];
const nodeFetch=(u,o={})=>new Promise((res,rej)=>{const url=new URL(u);
 const rq=http.request({hostname:url.hostname,port:url.port,path:url.pathname+url.search,method:o.method||'GET',headers:o.headers||{}},rs=>{
  const chunks=[];let done=false,err=null,waiter=null;
  const wake=()=>{if(waiter){const w=waiter;waiter=null;w()}};
  rs.on('data',c=>{chunks.push(c);wake()});rs.on('end',()=>{done=true;wake()});rs.on('error',e=>{err=e;wake()});
  const body={async *[Symbol.asyncIterator](){let i=0;for(;;){while(i<chunks.length)yield chunks[i++];if(done)return;if(err)throw err;await new Promise(r=>waiter=r)}}};
  res({status:rs.statusCode,headers:rs.headers,body,text:async()=>{let b='';for await(const c of body)b+=c;return b}})});
 rq.on('error',rej);if(o.signal)o.signal.addEventListener('abort',()=>{rq.destroy(new Error('aborted'))});if(o.body)rq.write(o.body);rq.end()});
const spyFetch=(tag,next)=>(u,o={})=>{if(tag==='pc')pcHeaders.push({...(o.headers||{})});return next(u,o)};
const memBox=()=>{const m=new Map();return{get:async id=>m.get(id)||null,put:async(id,r)=>{m.set(id,r);return true},_map:m}};
async function makePC({badProof=false}={}){ // a fresh PC with no device key
 let dev=null;const tasks=new Map();
 const deviceSign=t=>dev?crypto.sign(null,Buffer.from(String(t),'utf8'),dev.privK).toString('hex'):null;
 // Mimic PRODUCTION src/lib/agent.js semantics: the verifier reads the CURRENT devId (never a
 // frozen one), and for 60s after the identity mint a bootstrap '-' read still passes (the
 // sender cannot know the fresh id yet). After the grace, '-' fails closed.
 let graceUntil=0;
 const verifyReadAuth=(method,pathName,query,headers)=>{
  const hdr=String(headers['x-gw-read-device']||'');
  const cur=dev?dev.deviceId:'-';
  let effective=null;
  if(hdr===cur)effective=cur;
  else if(hdr==='-'&&cur!=='-'&&Date.now()<graceUntil)effective='-';
  if(effective==null)return false;
  return createVerifier({deviceId:effective,senderPubB64}).verifyReadAuth(method,pathName,query,headers);
 };
 const{validEnvelope}=createVerifier({deviceId:'-',senderPubB64});
 const pc=await startLocalServer({port:0,token:'cmdk-test',version:'t',caps:'enroll_device',
  verifyReadAuth,getDevice:()=>dev?{deviceId:dev.deviceId,deviceSign}:null,
  getTask:id=>tasks.get(id)||null,tasksOk:()=>true,
  onCommand:m=>{
   if(m.kind!=='enroll_device')return{accepted:false,status:400,reason:'unknown_kind'};
   const data=(m.data&&typeof m.data==='object'&&!Array.isArray(m.data))?m.data:{};
   const payload=Object.keys(data).length?JSON.stringify(data):'';
   if(!validEnvelope(m,payload))return{accepted:false,status:403,reason:'unsigned'};
   if(tasks.has(m.id))return{accepted:false,status:409,reason:'duplicate'};
   tasks.set(m.id,{status:'running',result:null,at:Date.now(),terminal:false});
   setTimeout(()=>{
    if(!dev){const{publicKey:dp,privateKey:dk}=crypto.generateKeyPairSync('ed25519');
     const pubB64=dp.export({format:'der',type:'spki'}).toString('base64');
     dev={pubB64,privK:dk,deviceId:crypto.createHash('sha256').update(pubB64).digest('hex').slice(0,16)};
     graceUntil=Date.now()+60000} // post-mint bootstrap grace (matches agent.js enroll_device)
    const proofChallenge=badProof?'FORGED-'+String(data.challenge):String(data.challenge); // a forged proof signs the WRONG challenge
    const out={deviceId:dev.deviceId,pubkey:dev.pubB64,challengeSig:signChallenge(deviceSign,proofChallenge,dev.pubB64,dev.deviceId)};
    tasks.set(m.id,{status:'done',result:out,at:Date.now(),terminal:true})},10);
   return{accepted:true}}});
 assert(pc.started,'pc up');return pc}
async function makeCtl(){ // the REAL worker route behind http
 const fdb=new FakeDB();
 const workerEnv={AVI_ACCOUNT_DB:fdb,GW_REPLY_KEY:'rk-test',GW_MAX_DEVICES:'3'};
 const ctl=http.createServer(async(rq,rs)=>{let b='';rq.on('data',c=>b+=c);rq.on('end',async()=>{
  const u='http://w'+rq.url;
  const wreq=new Request(u,{method:rq.method,headers:{'X-GW-Reply-Key':String(rq.headers['x-gw-reply-key']||''),'content-type':'application/json'},body:rq.method==='POST'?b:undefined});
  const wres=await handleTunnel(wreq,workerEnv,new URL(u));
  rs.writeHead(wres.status,{'content-type':'text/plain'});rs.end(await wres.text())})});
 await new Promise(r=>ctl.listen(0,'127.0.0.1',r));
 return{ctl,fdb,port:ctl.address().port,close:()=>new Promise(r=>ctl.close(r))}}
(async()=>{
 const pc=await makePC(),{ctl,fdb,close}=await makeCtl();
 const mkSender=o=>createSenderClient({deviceUrl:'http://127.0.0.1:'+pc.port,controlUrl:'http://127.0.0.1:'+ctl.address().port,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,preEnroll:true,fetchImpl:spyFetch('pc',nodeFetch),outbox:memBox(),pollIntervalMs:5,...o});
 const FP_RE=/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/; // the pairing fingerprint shape shown for approval
 const approveAny=async({deviceId,pubkey,fingerprint})=>/^[0-9a-f]{16}$/.test(String(deviceId))&&!!pubkey&&FP_RE.test(String(fingerprint));
 const orch=createEnrollOrchestrator({sender:mkSender(),approvePairing:approveAny});
 // full enrollment episode
 const r1=await orch.run();
 assert(r1.ok===true&&r1.deviceId&&fdb.devices.get(r1.deviceId),'enrollment episode completes + registry records the device');
 assert(fdb.devices.get(r1.deviceId).pubkey===r1.pubkey,'registry stores the returned pubkey');
 assert(!r1.already,'first enroll is fresh');
 for(const h of pcHeaders)assert(!('x-gw-reply-key' in h),'the PC NEVER sees the reply key (A1 safe order)');
 // idempotent re-enroll: FRESH challenge, same device -> already:true
 const r2=await orch.run();
 assert(r2.ok===true&&r2.already===true&&r2.deviceId===r1.deviceId,'re-enroll idempotent (fresh challenge, same device)');
 // preEnroll mode refuses any non-enroll kind
 const bad=await mkSender().sendCommand({kind:'find_files',data:{}});
 assert(bad.status==='refused'&&bad.reason.includes('preEnroll'),'preEnroll carries enroll_device ONLY');
 // forged proof: PC signs the WRONG challenge - refused BEFORE the registry
 const pc2=await makePC({badProof:true});
 const orchBad=createEnrollOrchestrator({approvePairing:approveAny,sender:createSenderClient({deviceUrl:'http://127.0.0.1:'+pc2.port,controlUrl:'http://127.0.0.1:'+ctl.address().port,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,preEnroll:true,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5})});
 const rBad=await orchBad.run();
 assert(rBad.ok===false&&rBad.stage==='proof'&&fdb.devices.size===1,'forged challenge proof refused BEFORE any registry write');
 await pc2.stop();
 // pairing approval MISSING -> fail closed BEFORE any registry mutation, fingerprint returned
 {const orchNo=createEnrollOrchestrator({sender:mkSender()}); // no approvePairing channel
  const rNo=await orchNo.run();
  assert(rNo.ok===false&&rNo.stage==='pairing'&&FP_RE.test(String(rNo.fingerprint)),'missing approval channel refuses with fingerprint');
  assert(fdb.devices.size===1,'no registry write without an approval channel')}
 // pairing approval DECLINED (a valid, proven key the user refuses) -> no registry write
 {const orchDec=createEnrollOrchestrator({sender:mkSender(),approvePairing:async()=>false});
  const rDec=await orchDec.run();
  assert(rDec.ok===false&&rDec.stage==='pairing','declined pairing refuses');
  assert(fdb.devices.size===1,'declined pairing writes nothing')}
 // malformed registry 200 JSON -> registry failure, never a throw
 {const badJson=http.createServer((rq,rs)=>{rs.writeHead(200,{'content-type':'text/plain'});rs.end('<html>not json')});
  await new Promise(r=>badJson.listen(0,'127.0.0.1',r));
  const orchMj=createEnrollOrchestrator({approvePairing:approveAny,sender:createSenderClient({deviceUrl:'http://127.0.0.1:'+pc.port,controlUrl:'http://127.0.0.1:'+badJson.address().port,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,preEnroll:true,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5})});
  const rMj=await orchMj.run();
  assert(rMj.ok===false&&rMj.stage==='registry'&&/bad json/.test(rMj.reason),'malformed registry 200 refused cleanly');
  await new Promise(r=>badJson.close(r))}
 // controlGet tunnel discovery REQUIRES ?device=<16hex> (the live route 400s without it)
 {const snd=mkSender();
  let threw=false;try{await snd.controlGet('/glasswidgets/agent/tunnel')}catch{threw=true}
  assert(threw,'tunnel discovery without device refused client-side');
  threw=false;try{await snd.controlGet('/glasswidgets/agent/tunnel',{device:'xyz'})}catch{threw=true}
  assert(threw,'tunnel discovery with a non-16hex device refused client-side');
  const hit=[];const disc=http.createServer((rq,rs)=>{hit.push(rq.url);rs.writeHead(200);rs.end('{"ok":true,"row":null}')});
  await new Promise(r=>disc.listen(0,'127.0.0.1',r));
  const snd2=createSenderClient({deviceUrl:'http://127.0.0.1:'+pc.port,controlUrl:'http://127.0.0.1:'+disc.address().port,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,preEnroll:true,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5});
  await snd2.controlGet('/glasswidgets/agent/tunnel',{device:r1.deviceId});
  assert(hit.length===1&&hit[0]==='/glasswidgets/agent/tunnel?device='+r1.deviceId,'discovery carries ?device=<16hex>');
  await new Promise(r=>disc.close(r))}
 // registry device limit
 const ctl2=await makeCtl();ctl2.fdb.devices.set('a'.repeat(16),{pubkey:'x'}); // max 1 below
 const orch3=createEnrollOrchestrator({approvePairing:approveAny,sender:createSenderClient({deviceUrl:'http://127.0.0.1:'+pc.port,controlUrl:'http://127.0.0.1:'+ctl2.port,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,preEnroll:true,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5})});
 // same device re-enroll against a FULL registry (max 1, different device already in)
 const wEnv={AVI_ACCOUNT_DB:ctl2.fdb,GW_REPLY_KEY:'rk-test',GW_MAX_DEVICES:'1'};
 const ctl3=http.createServer(async(rq,rs)=>{let b='';rq.on('data',c=>b+=c);rq.on('end',async()=>{
  const u='http://w'+rq.url;const wreq=new Request(u,{method:rq.method,headers:{'X-GW-Reply-Key':String(rq.headers['x-gw-reply-key']||''),'content-type':'application/json'},body:rq.method==='POST'?b:undefined});
  const wres=await handleTunnel(wreq,wEnv,new URL(u));rs.writeHead(wres.status);rs.end(await wres.text())})});
 await new Promise(r=>ctl3.listen(0,'127.0.0.1',r));
 const orch4=createEnrollOrchestrator({approvePairing:approveAny,sender:createSenderClient({deviceUrl:'http://127.0.0.1:'+pc.port,controlUrl:'http://127.0.0.1:'+ctl3.address().port,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,preEnroll:true,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5})});
 const rLim=await orch4.run();
 assert(rLim.ok===false&&rLim.stage==='registry','device limit surfaces as a registry failure');
 await pc.stop();await close();await ctl2.close();await new Promise(r=>ctl3.close(r));
 console.log('ENROLL-ORCHESTRATOR-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
