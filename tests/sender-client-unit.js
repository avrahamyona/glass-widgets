// A5 sender client tests against the REAL local server (src/lib/localserver.js startLocalServer)
// with the REAL extracted verifier and a REAL device key: health nonce proof, X-GW-Key gating,
// request-bound device-signed responses (headers + exact raw body), durable outbox fail-closed,
// deadlines and strict URL validation. No hand-rolled fake contract anywhere.
const assert=require('assert'),crypto=require('crypto'),http=require('http');
const{createSenderClient}=require('../server/lib/sender-client.js');
const{createVerifier}=require('../server/lib/verify.js');
const{startLocalServer}=require('../src/lib/localserver.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519'); // sender (worker) key
const{publicKey:DPUB,privateKey:DPRIV}=crypto.generateKeyPairSync('ed25519'); // device key
const SIGN_PRIV=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
const DEV_PUB_B64=DPUB.export({format:'der',type:'spki'}).toString('base64');
const DEV=crypto.createHash('sha256').update(DPUB.export({format:'der',type:'spki'})).digest('hex').slice(0,16);
const senderPubB64=PUB.export({format:'der',type:'spki'}).toString('base64');
// fetchImpl over node http - exposes status + headers + text (no global fetch on node 15)
const nodeFetch=(u,o={})=>new Promise((res,rej)=>{const url=new URL(u);
 const rq=http.request({hostname:url.hostname,port:url.port,path:url.pathname+url.search,method:o.method||'GET',headers:o.headers||{}},rs=>{let b='';rs.on('data',c=>b+=c);rs.on('end',()=>res({status:rs.statusCode,headers:rs.headers,json:async()=>JSON.parse(b),text:async()=>b}))});
 rq.on('error',rej);if(o.signal)o.signal.addEventListener('abort',()=>{rq.destroy(new Error('aborted'))});if(o.body)rq.write(o.body);rq.end()});
const memBox=()=>{const m=new Map();return{get:async id=>m.get(id)||null,put:async(id,r)=>{m.set(id,r);return true},_map:m}};
(async()=>{
 const tasks=new Map();
 const srv=await startLocalServer({port:0,token:'cmdk-test',version:'t',caps:'find_files',
  verifyReadAuth:createVerifier({deviceId:DEV,senderPubB64}).verifyReadAuth,
  getDevice:()=>({deviceId:DEV,deviceSign:t=>crypto.sign(null,Buffer.from(String(t),'utf8'),DPRIV).toString('hex')}),
  getTask:id=>tasks.get(id)||null,tasksOk:()=>true,
  onCommand:m=>{if(tasks.has(m.id))return{accepted:false,reason:'duplicate',status:409};tasks.set(m.id,{status:'accepted',result:null,at:Date.now(),terminal:false});return{accepted:true}}}); // idempotent intake, as the ledger-backed handler behaves
 assert(srv.started,'server started');
 const port=srv.port,base='http://127.0.0.1:'+port;
 const mk=(o={})=>createSenderClient({workerUrl:base,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,device:DEV,devicePub:DEV_PUB_B64,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5,...o});
 // full cycle against the real server: health proof -> signed POST -> signed poll
 const c=mk();
 const s1=await c.sendCommand({kind:'find_files',data:{query:'dad'}});
 assert(s1.status==='accepted'&&/^[0-9a-f-]{36}$/.test(s1.id),'accepted via the real server (health proof + X-GW-Key + reply key)');
 const p1=await c.pollTask(s1.id);
 assert(p1.status==='accepted'&&p1.trusted===true,'device-signed response verifies against the request-bound canonical (headers + raw body + request ts/nonce)');
 tasks.set(s1.id,{status:'done',result:{n:1},at:Date.now(),terminal:true});
 const t1=await c.waitTerminal(s1.id,{timeoutMs:2000});
 assert(t1.status==='done'&&t1.trusted===true,'trusted terminal completes the wait');
 // tampered raw body fails the proof (proxy that flips the body AFTER the server signs it)
 const evil=http.createServer(async(rq,rs)=>{const u='http://127.0.0.1:'+port+rq.url;const r=await nodeFetch(u,{method:rq.method,headers:rq.headers});let b=await r.text();if(rq.url.startsWith('/task'))b=b.replace('"accepted"','"done"');const h={...r.headers};delete h['content-length']; // body length changed - never forward a stale length
 rs.writeHead(r.status,h);rs.end(b)});
 await new Promise(r=>evil.listen(0,'127.0.0.1',r));
 const cE=mk({workerUrl:'http://127.0.0.1:'+evil.address().port});
 tasks.set('cmd-tamper01',{status:'accepted',result:null,at:Date.now(),terminal:false}); // a task whose body the proxy will rewrite
 const pE=await cE.pollTask('cmd-tamper01');assert(pE.status==='done'&&pE.trusted===false,'tampered body fails the device sig (fail closed)');evil.close();
 // no X-GW-Key -> the real server refuses (proves the header is really required)
 const noKey=(u,o={})=>{o={...o,headers:{...(o.headers||{})}};delete o.headers['X-GW-Key'];return nodeFetch(u,o)};
 const cK=createSenderClient({workerUrl:base,replyKey:'rk-test',cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,device:DEV,devicePub:DEV_PUB_B64,fetchImpl:noKey,outbox:memBox()});
 assert((await cK.sendCommand({kind:'find_files',data:{}})).reason==='device_unproven','without X-GW-Key the health proof fails closed');
 // outbox fail-closed: read failure pauses, put false blocks the network, unknown keeps the id
 const badRead={get:async()=>{throw new Error('disk')},put:async()=>true};
 const cB=mk({outbox:badRead});
 const sB=await cB.sendCommand({kind:'find_files',data:{}});
 assert(sB.status==='unknown'&&sB.reason==='outbox_read_failed'&&/^[0-9a-f-]{36}$/.test(sB.id),'outbox read failure pauses WITH the id');
 const falsePut={get:async()=>null,put:async()=>false};
 const cP=mk({outbox:falsePut});
 assert((await cP.sendCommand({kind:'find_files',data:{}})).reason==='outbox_commit_failed','put false blocks the network');
 // idempotent retry: exact stored envelope; same id + different content refused
 const box=memBox(),c3=mk({outbox:box});
 const prep=await c3.prepare({kind:'read_file',data:{path:'/a.txt'}});
 assert((await c3.send(prep)).status==='accepted','first send accepted');
 const s3b=await c3.send(prep);assert(s3b.status==='duplicate','second send resolves as duplicate');
 await assert.rejects(()=>c3.prepare({id:prep.id,kind:'read_file',data:{path:'/b.txt'}}),'same id + different content refused');
 // network failure returns unknown WITH the id
 const c4=mk({workerUrl:'http://127.0.0.1:1'});
 const s4=await c4.sendCommand({kind:'find_files',data:{query:'x'}});
 assert(s4.status==='unknown'&&/^[0-9a-f-]{36}$/.test(s4.id),'network failure returns unknown WITH the original id');
 // strict URL validation
 assert.throws(()=>mk({workerUrl:'http://evil.example'}),'http origin refused');
 assert.throws(()=>mk({workerUrl:'ftp://127.0.0.1:'+port}),'non-http(s) protocol refused even on localhost');
 assert.throws(()=>mk({workerUrl:base+'/sub'}),'non-root path refused (never silently dropped)');
 // single-shot + unknown handling
 const w5=await c.waitTerminal('cmd-never',{timeoutMs:0});
 assert(w5.status==='timeout'&&w5.last.reason==='not_found','timeoutMs:0 = exactly one poll (404 is not execution proof)');
 if(srv.stop)await srv.stop();
 console.log('SENDER-CLIENT-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
