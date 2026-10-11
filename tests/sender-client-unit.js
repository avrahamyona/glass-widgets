// A5 sender client unit tests - fully offline via an injected mock fetch.
// Covers: signed POST shape, idempotent retry (same id, 409 = cached outcome, never a new id),
// signed task polling to a terminal state, 'unknown' returned (never re-executed), timeout,
// worker refusals, fail-closed construction, kind allowlist before ANY network use.
const assert=require('assert'),crypto=require('crypto');
const{createSenderClient}=require('../server/lib/sender-client.js');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const SIGN_PRIV=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
const pubK=()=>crypto.createPublicKey({key:PUB.export({format:'der',type:'spki'}),format:'der',type:'spki'});
const DEV=crypto.createHash('sha256').update('devpub').digest('hex').slice(0,16);
const verify=(fields,sig)=>crypto.verify(null,Buffer.from(fields.join('\n'),'utf8'),pubK(),Buffer.from(sig,'hex'));
const res=(status,body)=>({status,json:async()=>body,text:async()=>typeof body==='string'?body:JSON.stringify(body||'')});
(async()=>{
 const calls=[];
 const client=createSenderClient({workerUrl:'https://w.example/',replyKey:'rk-test',signPrivate:SIGN_PRIV,device:DEV,fetchImpl:async(u,o)=>{calls.push([u,o]);
  if(String(u).includes('/command'))return res(202,{ok:true});
  if(String(u).includes('/task'))return res(200,{id:'x',status:'done',result:{n:1}});
  return res(404,'nope');},pollIntervalMs:1});
 // send: signed envelope POSTed with the reply-key header, fresh UUID id
 const s1=await client.sendCommand({kind:'find_files',data:{query:'dad'}});
 assert(s1.status==='accepted'&&/^[0-9a-f-]{36}$/.test(s1.id),'accepted with uuid id');
 const[u1,o1]=calls[0];
 assert(u1==='https://w.example/glasswidgets/agent/command'&&o1.headers['X-GW-Reply-Key']==='rk-test','post path + reply key header (header only - never in the URL)');
 assert(!u1.includes('rk-test'),'reply key never leaks into the URL');
 const env1=JSON.parse(o1.body);
 assert(verify([DEV,s1.id,'find_files',String(env1.ts),String(env1.exp),JSON.stringify({query:'dad'})],env1.sig),'v2 envelope signature verifies against the device-first canonical');
 // idempotent retry: SAME id + SAME payload; a 409 returns the cached outcome, never a new id
 const c2=createSenderClient({workerUrl:'https://w.example',replyKey:'rk',signPrivate:SIGN_PRIV,device:DEV,fetchImpl:async()=>res(409,{outcome:{status:'done',result:{n:1}}})});
 const s2=await c2.sendCommand({id:s1.id,kind:'find_files',data:{query:'dad'}});
 assert(s2.status==='duplicate'&&s2.id===s1.id&&s2.outcome.status==='done','409 = cached outcome for the SAME id');
 // signed polling: read canonical in the URL verifies; terminal state returned as-is
 const t=await client.pollTask('cmd-0000001');
 assert(t.status==='done','terminal status returned');
 const q=new URL(calls[calls.length-1][0]).searchParams;
 const query='id=cmd-0000001';
 assert(verify(['GET','/task',query,q.get('ts'),q.get('nonce'),DEV],q.get('sig')),'poll read signature verifies');
 // waitTerminal: running -> done over two polls; unknown is RETURNED, never re-executed
 let n=0;const seq=[{status:'accepted'},{status:'running'},{status:'done'}];
 const c3=createSenderClient({workerUrl:'https://w.example',replyKey:'rk',signPrivate:SIGN_PRIV,device:DEV,pollIntervalMs:1,fetchImpl:async()=>res(200,seq[Math.min(n++,seq.length-1)])});
 assert((await c3.waitTerminal('cmd-0000002')).status==='done','polls until terminal');
 const c4=createSenderClient({workerUrl:'https://w.example',replyKey:'rk',signPrivate:SIGN_PRIV,device:DEV,pollIntervalMs:1,fetchImpl:async()=>res(200,{status:'unknown'})});
 assert((await c4.waitTerminal('cmd-0000003')).status==='unknown','unknown returned for manual reconciliation - no blind re-execution');
 const c4b=createSenderClient({workerUrl:'https://w.example',replyKey:'rk',signPrivate:SIGN_PRIV,device:DEV,pollIntervalMs:1,fetchImpl:async()=>res(200,{status:'running'})});
 assert((await c4b.waitTerminal('cmd-0000004',{timeoutMs:0})).status==='timeout','timeout returns, does not throw');
 // refusals + fail-closed
 const c5=createSenderClient({workerUrl:'https://w.example',replyKey:'rk',signPrivate:SIGN_PRIV,device:DEV,fetchImpl:async()=>res(400,'bad_kind')});
 await assert.rejects(()=>c5.sendCommand({kind:'find_files',data:{}}),'worker refusal surfaces');
 let hit=false;const c6=createSenderClient({workerUrl:'https://w.example',replyKey:'rk',signPrivate:SIGN_PRIV,device:DEV,fetchImpl:async()=>{hit=true;return res(202)}});
 await assert.rejects(()=>c6.sendCommand({kind:'not_a_kind',data:{}}));assert(!hit,'kind allowlist checked BEFORE any network use');
 await assert.rejects(()=>c5.pollTask('x'),'poll refusal surfaces');
 assert.throws(()=>createSenderClient({workerUrl:'x',replyKey:'y',signPrivate:'z'}),'fetchImpl required - no implicit network');
 assert.throws(()=>createSenderClient({replyKey:'y',signPrivate:'z',fetchImpl:async()=>{}}),'missing config fails closed');
 console.log('SENDER-CLIENT-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
