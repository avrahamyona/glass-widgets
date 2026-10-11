// A5 sender client tests against the REAL local server (startLocalServer) - secret routing,
// Headers-compat proofs, health TTL, durable outbox fail-closed, deadlines, strict URLs.
const assert=require('assert'),crypto=require('crypto'),http=require('http');
const{createSenderClient,verifyDeviceSig}=require('../server/lib/sender-client.js');
const{createVerifier}=require('../server/lib/verify.js');
const{startLocalServer}=require('../src/lib/localserver.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const{publicKey:DPUB,privateKey:DPRIV}=crypto.generateKeyPairSync('ed25519');
const SIGN_PRIV=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
const DEV_PUB_B64=DPUB.export({format:'der',type:'spki'}).toString('base64');
const DEV=crypto.createHash('sha256').update(DPUB.export({format:'der',type:'spki'})).digest('hex').slice(0,16);
const senderPubB64=PUB.export({format:'der',type:'spki'}).toString('base64');
const seenHeaders=[];
const nodeFetch=(u,o={})=>new Promise((res,rej)=>{const url=new URL(u);
 const rq=http.request({hostname:url.hostname,port:url.port,path:url.pathname+url.search,method:o.method||'GET',headers:o.headers||{}},rs=>{
  const chunks=[];let done=false,err=null,waiter=null,destroyed=false;
  const wake=()=>{if(waiter){const w=waiter;waiter=null;w()}};
  rs.on('data',c=>{chunks.push(c);wake()});rs.on('end',()=>{done=true;wake()});rs.on('error',e=>{err=e;wake()});
  const body={async *[Symbol.asyncIterator](){let i=0;for(;;){while(i<chunks.length)yield chunks[i++];if(done)return;if(err)throw err;await new Promise(r=>waiter=r)}},
   getReader(){const it=this[Symbol.asyncIterator]();return{read:()=>it.next(),cancel:async()=>{destroyed=true;rs.destroy();await it.return()},releaseLock(){}}}};
  res({status:rs.statusCode,headers:rs.headers,body,text:async()=>{let b='';for await(const c of body)b+=c;return b},wasDestroyed:()=>destroyed});
 });
 rq.on('error',rej);if(o.signal)o.signal.addEventListener('abort',()=>{rq.destroy(new Error('aborted'))});if(o.body)rq.write(o.body);rq.end()});
const memBox=()=>{const m=new Map();return{get:async id=>m.get(id)||null,put:async(id,r)=>{m.set(id,r);return true},_map:m}};
(async()=>{
 const tasks=new Map();let healthHits=0;
 const srv=await startLocalServer({port:0,token:'cmdk-test',version:'t',caps:'find_files',
  verifyReadAuth:createVerifier({deviceId:DEV,senderPubB64}).verifyReadAuth,
  getDevice:()=>({deviceId:DEV,deviceSign:t=>crypto.sign(null,Buffer.from(String(t),'utf8'),DPRIV).toString('hex')}),
  getTask:id=>tasks.get(id)||null,tasksOk:()=>true,
  onCommand:m=>{if(tasks.has(m.id))return{accepted:false,reason:'duplicate',status:409};tasks.set(m.id,{status:'accepted',result:null,at:Date.now(),terminal:false});return{accepted:true}},
  log:(l,o)=>{if(o&&o.stage==='listening')return}});
 assert(srv.started,'server started');
 const port=srv.port,base='http://127.0.0.1:'+port;
 // count health proofs + capture whether the reply key EVER reaches the device origin
 const spy=(u,o={})=>{if(String(u).includes('/health'))healthHits++;seenHeaders.push([String(u),{...(o.headers||{})},o.method||'GET']);return nodeFetch(u,o)};
 let clock=Date.now();
 const mk=(o={})=>createSenderClient({deviceUrl:base,cmdKey:'cmdk-test',signPrivate:SIGN_PRIV,device:DEV,devicePub:DEV_PUB_B64,fetchImpl:spy,outbox:memBox(),pollIntervalMs:5,...o});
 // full cycle on the real server - secretless direct transport
 const c=mk();
 const s1=await c.sendCommand({kind:'find_files',data:{query:'dad'}});
 assert(s1.status==='accepted'&&s1.trusted===false&&/not a device execution proof/.test(s1.note),'202 = HTTP acceptance only, no execution claim');
 for(const[u,h]of seenHeaders)assert(!('x-gw-reply-key' in h)&&!u.includes('rk-test'),'reply key NEVER reaches the device origin (path '+u+')'); // CRITICAL negative test
 let cmdPosts=()=>seenHeaders.filter(([u,h,m])=>u.includes('/cmd')&&m==='POST').length;
 const p1=await c.pollTask(s1.id);
 assert(p1.status==='accepted'&&p1.trusted===true,'request-bound device sig verifies (headers + exact raw body)');
 tasks.set(s1.id,{status:'done',result:{n:1},at:Date.now(),terminal:true});
 assert((await c.waitTerminal(s1.id,{timeoutMs:2000})).trusted===true,'trusted terminal completes');
 // Headers-object compat (real fetch Headers): valid sig must verify through headers.get
 const body='{"ok":true}';const ts=Date.now(),nonce='abcdef123456';
 const canon=[DEV,'GET','/task','id=x',String(ts),nonce,'200',crypto.createHash('sha256').update(body,'utf8').digest('hex')].join('\n');
 const sig=crypto.sign(null,Buffer.from(canon,'utf8'),DPRIV).toString('hex');
 const H=new Headers({'x-gw-device':DEV,'x-gw-device-sig':sig});
 assert(verifyDeviceSig(crypto.createPublicKey({key:Buffer.from(DEV_PUB_B64,'base64'),format:'der',type:'spki'}),DEV,{headers:H,method:'GET',path:'/task',query:'id=x',reqTs:ts,reqNonce:nonce,status:200,rawBody:body})===true,'standard Headers object verifies (round-7 repro)');
 // tampered body via proxy (stale content-length handled)
 const evil=http.createServer(async(rq,rs)=>{const r=await nodeFetch('http://127.0.0.1:'+port+rq.url,{method:rq.method,headers:rq.headers});let b=await r.text();if(rq.url.startsWith('/task'))b=b.replace('"accepted"','"done"');const h={...r.headers};delete h['content-length'];rs.writeHead(r.status,h);rs.end(b)});
 await new Promise(r=>evil.listen(0,'127.0.0.1',r));
 const cE=mk({deviceUrl:'http://127.0.0.1:'+evil.address().port});
 tasks.set('cmd-tamper01',{status:'accepted',result:null,at:Date.now(),terminal:false});
 const pE=await cE.pollTask('cmd-tamper01');assert(pE.status==='done'&&pE.trusted===false,'tampered body fails the device sig (fail closed)');evil.close();
 // secret routing constructor rules
 assert.throws(()=>mk({replyKey:'rk-test'}),'replyKey without controlUrl refused');
 assert.throws(()=>mk({controlUrl:base,replyKey:'rk-test'}),'controlUrl identical to deviceUrl refused (round-8 repro)');
 const ctl=http.createServer((rq,rs)=>{seenHeaders.push(['CONTROL'+rq.url,{...rq.headers}]);rs.writeHead(200,{'content-type':'application/json'}).end('{"ok":true}')});
 await new Promise(r=>ctl.listen(0,'127.0.0.1',r));
 const cCtl=mk({controlUrl:'http://127.0.0.1:'+ctl.address().port,replyKey:'rk-test'});
 await assert.rejects(()=>cCtl.controlGet('/health'),'non-allowlisted control endpoint refused');
 const cg=await cCtl.controlGet('/glasswidgets/agent/tunnel');
 assert(cg.status===200&&seenHeaders.some(([u,h])=>u.startsWith('CONTROL')&&h['x-gw-reply-key']==='rk-test'),'reply key rides the CONTROL origin on an allowlisted endpoint');
 for(const[u,h]of seenHeaders)if(!u.startsWith('CONTROL'))assert(h&&!('x-gw-reply-key' in h),'reply key still never on the device origin');
 ctl.close();
 // health TTL: cached within TTL, re-proven after TTL, resetIdentity forces re-proof
 const cH=mk({nowFn:()=>clock}); // fresh client with the fake clock - no cached proof
 const h0=healthHits;await cH.ensureDevice();const h1=healthHits;await cH.ensureDevice();
 assert(healthHits===h1&&h1===h0+1,'health proof cached within TTL');
 clock+=400000;await cH.ensureDevice();assert(healthHits===h1+1,'health proof re-fetched after TTL');
 cH.resetIdentity();await cH.ensureDevice();assert(healthHits===h1+2,'resetIdentity forces a fresh proof');
 // outbox fail-closed
 const cB=mk({outbox:{get:async()=>{throw new Error('disk')},put:async()=>true}});
 const sB=await cB.sendCommand({kind:'find_files',data:{}});
 assert(sB.status==='unknown'&&sB.reason==='outbox_read_failed'&&/^[0-9a-f-]{36}$/.test(sB.id),'outbox read failure pauses WITH the id');
 const cP=mk({outbox:{get:async()=>null,put:async()=>false}});
 assert((await cP.sendCommand({kind:'find_files',data:{}})).reason==='outbox_commit_failed','put false blocks the network');
 const cC=mk({outbox:{get:async()=>({envelope:{id:'x',kind:'nope'}}),put:async()=>true}});
 assert((await cC.send({id:'x'})).reason==='no_valid_durable_envelope','stored record must pass schema validation before the wire');
 // idempotent retry: exact stored envelope; same id + different content refused
 const box=memBox(),c3=mk({outbox:box});
 const prep=await c3.prepare({kind:'read_file',data:{path:'/a.txt'}});
 assert((await c3.send(prep)).status==='accepted','first send accepted');
 assert((await c3.send(prep)).status==='duplicate','resend resolves as duplicate');
 await assert.rejects(()=>c3.prepare({id:prep.id,kind:'read_file',data:{path:'/b.txt'}}),'same id + different content refused');
 // network failure returns unknown WITH the id
 const s4=await mk({deviceUrl:'http://127.0.0.1:1'}).sendCommand({kind:'find_files',data:{query:'x'}});
 assert(s4.status==='unknown'&&/^[0-9a-f-]{36}$/.test(s4.id),'network failure returns unknown WITH the original id');
 // utf8 byte cap: a large multi-byte body is refused
 const big=http.createServer((rq,rs)=>{rs.writeHead(200,{'content-type':'application/json'});rs.end(JSON.stringify({status:'done',pad:'\u05d0'.repeat(140000)}))}); // ~270KB utf8
 await new Promise(r=>big.listen(0,'127.0.0.1',r));
 const pBig=await mk({deviceUrl:'http://127.0.0.1:'+big.address().port}).pollTask('cmd-bigbody1');
 assert(pBig.status==='unknown'&&pBig.reason==='network','over-cap utf8 body refused');big.close();
 // stream cancellation: an infinite body loses to the deadline AND its reader is cancelled
 let cancelled=false;
 const infFetch=()=>Promise.resolve({status:200,headers:{},body:new ReadableStream({start(c){let n=0;const push=()=>{try{c.enqueue(new Uint8Array(1024))}catch{return}setTimeout(push,0)};push()},cancel(){cancelled=true}})});
 const pInf=await mk({fetchImpl:infFetch,requestTimeoutMs:50}).pollTask('cmd-stream01');
 assert(pInf.status==='unknown'&&cancelled===true,'infinite stream times out AND the reader is cancelled/released');
 // expiry re-checked AFTER health, immediately before POST: the clock jumps during ensureDevice
 const boxE=memBox();let jump=false;
 const cX=mk({outbox:boxE,nowFn:()=>Date.now()+(jump?120000:0)});
 const pX=await cX.prepare({kind:'find_files',data:{}});
 const postsBefore=cmdPosts();
 jump=true; // health proof now runs with a clock past the envelope exp
 const sX=await cX.send(pX);
 assert(sX.status==='expired'&&cmdPosts()===postsBefore,'expired after health = NO POST (round-8 repro)');
 // device binding is required: a stored envelope with another/missing device never flies
 const boxD=memBox();await boxD.put('cmd-otherdev',{envelope:{id:'cmd-otherdev',kind:'find_files',device:'0'.repeat(16),ts:Date.now(),exp:Date.now()+30000,sig:'0'.repeat(128),data:{}},receipt:null,at:Date.now()});
 assert((await mk({outbox:boxD}).send({id:'cmd-otherdev'})).reason==='no_valid_durable_envelope','other-device envelope refused');
 const boxI=memBox();await boxI.put('cmd-noidmtch',{envelope:{id:'cmd-DIFFERENT',kind:'find_files',device:DEV,ts:Date.now(),exp:Date.now()+30000,sig:'0'.repeat(128),data:{}},receipt:null,at:Date.now()});
 assert((await mk({outbox:boxI}).send({id:'cmd-noidmtch'})).reason==='envelope_id_mismatch','envelope id must match the requested id');
 // text-only transports refused by default, allowed test-only
 const txtOnly=()=>Promise.resolve({status:200,headers:{},text:async()=>'{}'});
 assert((await mk({fetchImpl:txtOnly}).pollTask('cmd-textonly')).reason==='network','text-only transport refused by default (not stream-bounded)');
 assert(mk({fetchImpl:txtOnly,allowTextTransport:true}),'text-only transport allowed only with the explicit TEST-ONLY flag');
 // TTL contract: 120s/300s roundtrip prepare+send; out-of-contract ttls refused at prepare
 const cT=mk();
 const p120=await cT.prepare({kind:'find_files',data:{},ttlMs:120000});
 assert((await cT.send(p120)).status==='accepted','ttl 120s roundtrips through the shared contract');
 const p300=await cT.prepare({kind:'find_files',data:{},ttlMs:300000});
 assert((await cT.send(p300)).status==='accepted','ttl 300s (contract max) roundtrips');
 await assert.rejects(()=>cT.prepare({kind:'find_files',data:{},ttlMs:999}),'ttl under contract min refused');
 await assert.rejects(()=>cT.prepare({kind:'find_files',data:{},ttlMs:300001}),'ttl over contract max refused');
 await assert.rejects(()=>cT.prepare({kind:'find_files',data:{},ttlMs:1500.5}),'non-integer ttl refused');
 // late-response cleanup: a fetchImpl that ignores abort and resolves AFTER the deadline -
 // its late body must be cancelled/released, the request signal aborted
 let lateCancelled=false,lateSignal=null;
 const lateFetch=(u,o)=>{lateSignal=o.signal;return new Promise(res=>setTimeout(()=>{let closed=false;
  res({status:200,headers:{},body:new ReadableStream({start(c){if(!closed){c.enqueue(new TextEncoder().encode('{"ok":true}'));closed=true}},cancel(){lateCancelled=true}})})},100))};
 const pLate=await mk({fetchImpl:lateFetch,requestTimeoutMs:30}).pollTask('cmd-late0001');
 assert(pLate.status==='unknown'&&pLate.reason==='network','late fetch loses to the deadline');
 await new Promise(r=>setTimeout(r,200));
 assert(lateSignal&&lateSignal.aborted===true,'request signal aborted on timeout');
 assert(lateCancelled===true,'late response body cancelled/released, never left locked (round-8 repro)');
 // strict URLs + single-shot
 assert.throws(()=>mk({deviceUrl:'http://evil.example'}),'http origin refused');
 assert.throws(()=>mk({deviceUrl:'ftp://127.0.0.1:'+port}),'non-http(s) refused even on localhost');
 assert.throws(()=>mk({deviceUrl:base+'/sub'}),'non-root path refused');
 const w5=await c.waitTerminal('cmd-never',{timeoutMs:0});
 assert(w5.status==='timeout'&&w5.last.reason==='not_found','timeoutMs:0 = exactly one poll');
 if(srv.stop)await srv.stop();
 console.log('SENDER-CLIENT-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
