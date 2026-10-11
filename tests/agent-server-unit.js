// Own-server unit tests: run the embedded local server directly (Electron-free module).
const{startLocalServer,BODY_CAP}=require('../src/lib/localserver');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const TOKEN='test-key-123';

async function main(){
 // 1) refuses to start without a token
 {const r=await startLocalServer({port:0,token:'',version:'x',caps:'',onCommand:()=>({accepted:true})});
  assert(r.started===false&&r.reason==='no-token','no-token refuses: '+JSON.stringify(r))}

 const calls=[];
 const logs=[];
 const r=await startLocalServer({port:0,token:TOKEN,version:'0.4.61',caps:'approve,update',
  log:(l,o)=>logs.push({l,...o}),
  onCommand:m=>{calls.push(m);return m.kind==='bad_kind'?{accepted:false,reason:'unknown_kind'}:{accepted:true}}});
 assert(r.started&&r.port>0,'started on ephemeral port');
 const U='http://127.0.0.1:'+r.port;
 const J=async(path,opts)=>{const res=await fetch(U+path,opts);let body=null;try{body=await res.json()}catch{}return{status:res.status,body}};

 // 2) auth: no key / wrong key -> 403, right key -> pass
 assert((await J('/health')).status===403,'no key -> 403');
 assert((await J('/health',{headers:{'X-GW-Key':'nope'}})).status===403,'wrong key -> 403');
 assert(logs.some(l=>l.stage==='auth_fail'),'auth_fail audited');

 // 3) health
 {const h=await J('/health',{headers:{'X-GW-Key':TOKEN}});
  assert(h.status===200&&h.body.ok&&h.body.v==='0.4.61'&&h.body.caps==='approve,update','health: '+JSON.stringify(h.body))}

 // 4) command intake
 {const bad=await J('/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:'not json'});
  assert(bad.status===400,'bad json -> 400');
  const noKind=await J('/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:'{"foo":1}'});
  assert(noKind.status===400,'missing kind/id -> 400');
  const refused=await J('/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:JSON.stringify({id:'c1',kind:'bad_kind'})});
  assert(refused.status===409&&refused.body.reason==='unknown_kind','refused -> 409: '+JSON.stringify(refused.body));
  const ok=await J('/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:JSON.stringify({id:'c2',kind:'find_files',query:'x'})});
  assert(ok.status===202&&ok.body.ok,'accepted -> 202');
  assert(calls.length===2&&calls[1].kind==='find_files'&&calls[1].query==='x','handler received the command object');
  assert(logs.some(l=>l.stage==='cmd'&&l.accepted===true),'cmd acceptance audited')}

 // 5) the whole point: a command far beyond the worker envelope (4000) passes here
 {const big=JSON.stringify({id:'c3',kind:'run_command',command:'x'.repeat(40000)});
  const res=await J('/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:big});
  assert(res.status===202&&calls[2].command.length===40000,'40KB command passes the own server (worker would have rejected)')}

 // 5b) onCommand status mapping: auth refusals surface as 403, not a generic 409
 {const res=await J('/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:JSON.stringify({id:'c10',kind:'bad_kind'})});
  assert(res.status===409&&res.body.reason==='unknown_kind','handler refusal without status -> 409')}
 // 5c) handler-provided status wins (the 403 unsigned path in agent.js)
 {const r2=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',
   onCommand:()=>({accepted:false,status:403,reason:'unsigned'})});
  const res=await fetch('http://127.0.0.1:'+r2.port+'/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:JSON.stringify({id:'c11',kind:'find_files'})});
  assert(res.status===403,'handler status 403 surfaced');
  await r2.stop()}

 // 5d) health nonce: device-bound identity proof for the sender
 {const r3=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true}),
   getDevice:()=>({deviceId:'dev-1',deviceSign:t=>'sig('+t+')'})});
  const U3='http://127.0.0.1:'+r3.port;
  const h=await (await fetch(U3+'/health?nonce=abcdef123456',{headers:{'X-GW-Key':TOKEN}})).json();
  assert(h.deviceId==='dev-1'&&h.sig==='sig(dev-1\nabcdef123456)','nonce signed with the device key: '+JSON.stringify(h));
  const h2=await (await fetch(U3+'/health?nonce=../bad',{headers:{'X-GW-Key':TOKEN}})).json();
  assert(h2.ok&&!h2.sig,'bad nonce format -> plain health, no signature');
  const h3=await (await fetch(U3+'/health',{headers:{'X-GW-Key':TOKEN}})).json();
  assert(h3.ok&&!h3.deviceId,'no nonce -> no device fields');
  await r3.stop()}

 // 6) body cap still bounded
 {const huge=JSON.stringify({id:'c4',kind:'run_command',command:'x'.repeat(BODY_CAP)});
  const res=await fetch(U+'/cmd',{method:'POST',headers:{'X-GW-Key':TOKEN},body:huge});
  assert(res.status===413,'oversize body -> 413')}

 // 7) unknown path -> 404
 assert((await J('/nope',{headers:{'X-GW-Key':TOKEN}})).status===404,'404');

 // 8) resume regression (lesson 8): stop, restart, serves again
 await r.stop();
 {let down=false;try{await fetch(U+'/health',{headers:{'X-GW-Key':TOKEN},signal:AbortSignal.timeout(1500)})}catch{down=true}
  assert(down,'stopped server is down');
  const r2=await startLocalServer({port:r.port,token:TOKEN,version:'0.4.61',caps:'',onCommand:()=>({accepted:true})});
  assert(r2.started,'restart on the same port');
  const h=await fetch('http://127.0.0.1:'+r2.port+'/health',{headers:{'X-GW-Key':TOKEN}});
  assert(h.status===200,'serves after restart');
  await r2.stop()}

 console.log('AGENT-SERVER-UNIT: PASS');
}
main().catch(e=>{console.error('FAIL',e);process.exit(1)});
