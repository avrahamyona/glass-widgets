// Own-server unit tests: run the embedded local server directly (Electron-free module).
const{startLocalServer,BODY_CAP}=require('../src/lib/localserver');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const TOKEN='test-key-123';
const crypto=require('crypto');
// device-signed responses bind the response to the REQUEST: deviceId,method,path,query,readTs,readNonce,status,sha256(body)
const canon=(dev,method,path,q,ts,nonce,status,body)=>Buffer.from('sig:'+[dev,method,path,q,ts,nonce,String(status),crypto.createHash('sha256').update(body,'utf8').digest('hex')].join('\n')).toString('base64url');

async function main(){
 // 1) refuses to start without a token
 {const r=await startLocalServer({port:0,token:'',version:'x',caps:'',onCommand:()=>({accepted:true})});
  assert(r.started===false&&r.reason==='no-token','no-token refuses: '+JSON.stringify(r))}

 // 1b) bind address: the default is loopback-ONLY (a LAN-IP request must not be answered);
 // a non-loopback host is an explicit opt-in and is audited (bind_lan)
 {const os=require('os');
  const lan=(Object.values(os.networkInterfaces()).flat().find(i=>i&&i.family==='IPv4'&&!i.internal)||{}).address;
  if(lan){
   {const rl=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true})});
    let refused=false;try{const x=await fetch('http://'+lan+':'+rl.port+'/health',{headers:{'X-GW-Key':TOKEN},signal:AbortSignal.timeout(3000)});refused=(x.status!==200)}catch{refused=true}
    assert(refused,'default bind must be loopback-only - the LAN IP must not answer');
    assert(rl.host==='127.0.0.1','default host reported as loopback');
    await rl.stop()}
   const lanLogs=[];
   {const rw=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true}),host:'0.0.0.0',log:(l,o)=>lanLogs.push({l,...o})});
    assert(rw.started&&rw.host==='0.0.0.0','host opt-in reported in the result');
    const h=await fetch('http://'+lan+':'+rw.port+'/health',{headers:{'X-GW-Key':TOKEN},signal:AbortSignal.timeout(3000)});
    assert(h.status===200,'LAN bind answers on the LAN IP');
    assert(lanLogs.some(l=>l.stage==='bind_lan'),'LAN bind is audited (bind_lan stage)');
    await rw.stop()}
  }else console.log('note: no LAN interface here - bind test skipped');}

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

 // 9) /info + /task are PRIVATE READS: no verifyReadAuth -> 403 even with the right key
 {const r4=await startLocalServer({port:0,token:TOKEN,version:'0.4.62',caps:'approve,update',onCommand:()=>({accepted:true}),
   log:(l,o)=>logs.push({l,...o}),getInfo:()=>({deviceId:'dev-9',pubkey:'cHVi'}),getTask:()=>null,tasksOk:()=>true});
  const U4='http://127.0.0.1:'+r4.port;
  assert((await fetch(U4+'/info',{headers:{'X-GW-Key':TOKEN}})).status===403,'/info without signed-read auth -> 403 (public key is NOT enough)');
  assert((await fetch(U4+'/task?id=x',{headers:{'X-GW-Key':TOKEN}})).status===403,'/task without signed-read auth -> 403');
  assert(logs.some(l=>l.stage==='read_auth_fail'),'read auth failure audited');
  await r4.stop()}

 // 10) /info: signed-read auth passes; device-signed response when enrolled, deviceless marker else
 {const r5=await startLocalServer({port:0,token:TOKEN,version:'0.4.62',caps:'approve,update',onCommand:()=>({accepted:true}),
   verifyReadAuth:()=>true,getInfo:()=>({deviceId:'dev-9',pubkey:'cHVi'}),getDevice:()=>({deviceId:'dev-9',deviceSign:t=>Buffer.from('sig:'+t).toString('base64url')})});
  const U5='http://127.0.0.1:'+r5.port,H={headers:{'X-GW-Key':TOKEN}};
  const res=await fetch(U5+'/info',H);const txt=await res.text();const i=JSON.parse(txt);
  assert(i.ok&&i.v==='0.4.62'&&i.deviceId==='dev-9'&&i.pubkey==='cHVi','info body: '+txt);
  assert(res.headers.get('x-gw-device')==='dev-9'&&res.headers.get('x-gw-device-sig')===canon('dev-9','GET','/info','','','',200,txt),'info response signed over the request-bound canonical (not the bare body)');
  assert(res.headers.get('x-gw-device-sig')!==txt&&res.headers.get('x-gw-device-sig')!=='sig('+txt+')','the old body-only replayable scheme is gone');
  await r5.stop()}
 {const r5b=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true}),verifyReadAuth:()=>true}); // not enrolled
  const res=await fetch('http://127.0.0.1:'+r5b.port+'/info',{headers:{'X-GW-Key':TOKEN}});const i=await res.json();
  assert(i.ok&&i.deviceless===true&&!res.headers.get('x-gw-device-sig'),'unenrolled /info -> base shape with deviceless marker, unsigned');
  await r5b.stop()}

 // 11) /task: ledger-backed idempotent polling, device key REQUIRED (results are private)
 {const{createLedger}=require('../src/lib/ledger');
  const fs2=require('fs'),path2=require('path');
  const tf=path2.join(fs2.mkdtempSync('/tmp/gw-ledger-'),'ledger.json');
  const store=createLedger(tf);
  const H={headers:{'X-GW-Key':TOKEN}};
  {const r6=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true}),
    verifyReadAuth:()=>true,getTask:id=>store.get(id),tasksOk:()=>store.ok(),getDevice:()=>null});
   assert((await fetch('http://127.0.0.1:'+r6.port+'/task?id=t1',H)).status===503,'no enrolled device -> /task closed (503 no_device_key)');
   await r6.stop()}
  const r7=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true}),
   verifyReadAuth:()=>true,getTask:id=>store.get(id),tasksOk:()=>store.ok(),getDevice:()=>({deviceId:'dev-9',deviceSign:t=>Buffer.from('sig:'+t).toString('base64url')})});
  const U7='http://127.0.0.1:'+r7.port;
  {const resE=await fetch(U7+'/task?id=nope',H);const txtE=await resE.text();
   assert(resE.status===404,'unknown task -> 404');
   assert(resE.headers.get('x-gw-device-sig')===canon('dev-9','GET','/task','id=nope','','',404,txtE),'ERROR responses are device-signed too (a 404 cannot be replayed onto another task)');}
  store.put('t1',{status:'accepted',exp:Date.now()+300000});
  let res=await fetch(U7+'/task?id=t1',H);let j=await res.json();
  assert(j.status==='accepted'&&j.terminal===false,'accepted record visible');
  store.put('t1',{status:'done',note:'2 matches',result:{matches:2}});
  res=await fetch(U7+'/task?id=t1',H);const txt=await res.text();j=JSON.parse(txt);
  assert(j.status==='done'&&j.terminal===true&&j.result.matches===2,'terminal record served');
  assert(res.headers.get('x-gw-device-sig')===canon('dev-9','GET','/task','id=t1','','',200,txt),'task response signed over the request-bound canonical');
  store.put('t1',{status:'failed',note:'late'});
  j=await (await fetch(U7+'/task?id=t1',H)).json();
  assert(j.status==='done','terminal record idempotent (a late write cannot clobber)');
  const store2=createLedger(tf);
  assert(store2.get('t1').status==='done','record durable across reload');
  await r7.stop();
  fs2.writeFileSync(tf,'{corrupt');
  const store3=createLedger(tf);
  assert(store3.ok()===false,'corrupt ledger -> ok() false');
  assert(store3.put('t9',{status:'accepted',exp:Date.now()+1000})===false,'put on a down ledger REFUSES (never wipes evidence)');
  const r8=await startLocalServer({port:0,token:TOKEN,version:'x',caps:'',onCommand:()=>({accepted:true}),
   verifyReadAuth:()=>true,getTask:id=>store3.get(id),tasksOk:()=>store3.ok(),getDevice:()=>({deviceId:'d',deviceSign:t=>'s'})});
  assert((await fetch('http://127.0.0.1:'+r8.port+'/task?id=t1',H)).status===503,'broken ledger -> 503');
  await r8.stop()}

 console.log('AGENT-SERVER-UNIT: PASS');
}
main().catch(e=>{console.error('FAIL',e);process.exit(1)});
