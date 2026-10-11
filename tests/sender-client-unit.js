// A5 sender client unit tests - against a REAL transport: a node http server running the
// extracted PC verifier (server/lib/verify.js, the same code the standalone server uses),
// device-signed task responses, and a durable outbox. No mock-returns-done shortcuts.
const assert=require('assert'),crypto=require('crypto'),http=require('http');
const{createSenderClient}=require('../server/lib/sender-client.js');
const{createVerifier}=require('../server/lib/verify.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519'); // sender (worker) key
const{publicKey:DPUB,privateKey:DPRIV}=crypto.generateKeyPairSync('ed25519'); // device key
const SIGN_PRIV=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
const DEV_PUB_B64=DPUB.export({format:'der',type:'spki'}).toString('base64');
const DEV=crypto.createHash('sha256').update(DPUB.export({format:'der',type:'spki'})).digest('hex').slice(0,16);
const senderPubB64=PUB.export({format:'der',type:'spki'}).toString('base64');
const sha256=s=>crypto.createHash('sha256').update(s,'utf8').digest('hex');
const proofFor=(id,status,result)=>{const bodyHash=sha256(JSON.stringify(result));const ts=Date.now(),nonce=crypto.randomBytes(12).toString('hex');
 const sig=crypto.sign(null,Buffer.from([String(id),String(status),String(ts),nonce,bodyHash].join('\n'),'utf8'),DPRIV).toString('hex');return{ts,nonce,sig,bodyHash}};
// minimal fetchImpl over node http (no global fetch on the PC's node 15)
const nodeFetch=(u,o={})=>new Promise((res,rej)=>{const url=new URL(u);const rq=http.request({hostname:url.hostname,port:url.port,path:url.pathname+url.search,method:o.method||'GET',headers:o.headers||{},signal:o.signal},rs=>{let b='';rs.on('data',c=>b+=c);rs.on('end',()=>res({status:rs.statusCode,json:async()=>JSON.parse(b),text:async()=>b}))});rq.on('error',rej);if(o.body)rq.write(o.body);rq.end()});
const memBox=()=>{const m=new Map();return{get:async id=>m.get(id)||null,put:async(id,r)=>{m.set(id,r)},_map:m}};
(async()=>{
 // real transport: the extracted verifier guards reads; the intake + tasks are tiny but real HTTP
 const tasks=new Map(),posts=[];
 const server=http.createServer((rq,rs)=>{
  const url=new URL(rq.url,'http://x');
  if(url.pathname==='/task'){
   const v=createVerifier({deviceId:DEV,senderPubB64});
   if(!v.verifyReadAuth('GET','/task',url.search.slice(1),rq.headers)){rs.writeHead(403).end('read_auth');return}
   const id=url.searchParams.get('id');const t=tasks.get(id);
   if(!t){rs.writeHead(404).end('not_found');return}
   rs.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify(t));return;
  }
  if(url.pathname==='/glasswidgets/agent/command'&&rq.method==='POST'){
   if(rq.headers['x-gw-reply-key']!=='rk-test'){rs.writeHead(403).end('reply_key');return}
   let b='';rq.on('data',c=>b+=c);rq.on('end',()=>{const env=JSON.parse(b);posts.push(env);
    if(tasks.has(env.id)){rs.writeHead(409,{'content-type':'application/json'}).end(JSON.stringify({outcome:{status:tasks.get(env.id).status,result:tasks.get(env.id).result}}));return} // bare 409: NO proof
    tasks.set(env.id,{id:env.id,status:'running',result:null});
    rs.writeHead(202).end('accepted')});return;
  }
  rs.writeHead(404).end('nope');
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const port=server.address().port,base='http://127.0.0.1:'+port;
 const mk=(o={})=>createSenderClient({workerUrl:base,replyKey:'rk-test',signPrivate:SIGN_PRIV,device:DEV,devicePub:DEV_PUB_B64,fetchImpl:nodeFetch,outbox:memBox(),pollIntervalMs:5,...o});
 // gap 1+5: real signed read via HEADERS against the real verifier; real POST with reply key
 const c=mk();
 const s1=await c.sendCommand({kind:'find_files',data:{query:'dad'}});
 assert(s1.status==='accepted'&&/^[0-9a-f-]{36}$/.test(s1.id),'accepted via real transport');
 assert(posts.length===1&&posts[0].kind==='find_files','envelope reached the server');
 const p1=await c.pollTask(s1.id);
 assert(p1.status==='running'&&p1.trusted===false,'unsigned status is INFORMATIONAL ONLY - never terminal');
 const bad=await c.pollTask('cmd-zzzzzzzz');assert(bad.status==='unknown'&&bad.reason==='not_found','404 is not execution proof');
 // gap 2: only a device-PROVEN terminal completes the wait
 tasks.set(s1.id,{id:s1.id,status:'done',result:{n:1},proof:proofFor(s1.id,'done',{n:1})});
 const t1=await c.waitTerminal(s1.id,{timeoutMs:2000});
 assert(t1.status==='done'&&t1.trusted===true,'device-proven terminal completes');
 tasks.set(s1.id,{id:s1.id,status:'done',result:{n:1},proof:proofFor(s1.id,'done',{n:2})}); // body swapped after proof
 const t2=await c.pollTask(s1.id);assert(t2.trusted===false,'tampered body fails the proof (fail closed)');
 // gap 3: durable prepare before network; retry resends the EXACT stored envelope; id reuse refused
 const c2=mk();
 const prep=await c2.prepare({kind:'read_file',data:{path:'/a.txt'}});
 const box=memBox();const c3=mk({outbox:box});
 const prep3=await c3.prepare({kind:'read_file',data:{path:'/a.txt'}});
 const s3=await c3.send(prep3);assert(s3.status==='accepted','first send accepted');
 const s3b=await c3.send(prep3);assert(s3b.status==='duplicate'&&s3b.trusted===false,'bare 409 cached outcome is NOT trusted completion');
 await assert.rejects(()=>c3.prepare({id:prep3.id,kind:'read_file',data:{path:'/b.txt'}}),'same id + different content refused');
 const prep3c=await c3.prepare({id:prep3.id,kind:'read_file',data:{path:'/a.txt'}});assert(prep3c.reused===true&&prep3c.envelope.sig===prep3.envelope.sig,'retry returns the EXACT stored envelope (same sig - no rebuild)');
 // network failure keeps the id: status unknown, never a new id
 const c4=createSenderClient({workerUrl:'http://127.0.0.1:1',replyKey:'rk-test',signPrivate:SIGN_PRIV,device:DEV,devicePub:DEV_PUB_B64,fetchImpl:nodeFetch,outbox:memBox()});
 const s4=await c4.sendCommand({kind:'find_files',data:{query:'x'}});
 assert(s4.status==='unknown'&&s4.reason==='network'&&/^[0-9a-f-]{36}$/.test(s4.id),'network failure returns unknown WITH the original id');
 // gap 4: strict URL validation
 assert.throws(()=>mk({workerUrl:'http://evil.example'}),'http origin refused');
 assert.throws(()=>mk({workerUrl:base+'/?key=x'}),'query in workerUrl refused');
 assert.throws(()=>mk({workerUrl:'http://user:pw@127.0.0.1:'+port}),'userinfo refused');
 assert.throws(()=>mk({cmdPath:'/x?k=1'}),'query in path refused');
 // gap 5: explicit single-shot semantics + trusted timeout
 const c5=mk();
 const w5=await c5.waitTerminal('cmd-never',{timeoutMs:0});
 assert(w5.status==='timeout'&&w5.last.reason==='not_found','timeoutMs:0 = exactly one poll, then return');
 assert.throws(()=>createSenderClient({workerUrl:base,replyKey:'r',signPrivate:'s',fetchImpl:nodeFetch,outbox:memBox()}),'devicePub required - fail closed');
 assert.throws(()=>createSenderClient({workerUrl:base,replyKey:'r',signPrivate:'s',devicePub:DEV_PUB_B64,fetchImpl:nodeFetch}),'durable outbox required');
 server.close();
 console.log('SENDER-CLIENT-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
