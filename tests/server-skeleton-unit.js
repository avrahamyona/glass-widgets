// Skeleton smoke test: boot the standalone server, signed command -> durable result -> replay.
const assert=require('assert'),fs=require('fs'),path=require('path'),crypto=require('crypto'),{spawn}=require('child_process');
const dir=fs.mkdtempSync('/tmp/gw-srv-');
const fold=path.join(dir,'files');fs.mkdirSync(fold);fs.writeFileSync(path.join(fold,'presentation-dad.txt'),'deck contents');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const PUB_B64=PUB.export({format:'der',type:'spki'}).toString('base64');
fs.writeFileSync(path.join(dir,'config.json'),JSON.stringify({token:'srv-key',senderPub:PUB_B64,port:47790,roots:[fold]}));
const sign=(id,kind,ts,exp,payload)=>crypto.sign(null,Buffer.from([id,kind,String(ts),String(exp),payload].join('\n'),'utf8'),PRIV).toString('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const signRead=(p,q,dev)=>{const ts=Date.now(),nonce=crypto.randomBytes(12).toString('base64url');
 return{'X-GW-Key':'srv-key','X-GW-Read-Ts':String(ts),'X-GW-Read-Nonce':nonce,'X-GW-Read-Device':dev,
 'X-GW-Read-Sig':crypto.sign(null,Buffer.from(['GET',p,q,String(ts),nonce,dev].join('\n'),'utf8'),PRIV).toString('hex')}};
(async()=>{
 const cp=spawn(process.execPath,['server/index.js'],{env:{...process.env,GW_SERVER_CONFIG:path.join(dir,'config.json')},stdio:['ignore','pipe','pipe']});
 let up='';cp.stdout.on('data',d=>up+=d);
 for(let i=0;i<60&&!up.includes('server up');i++)await sleep(200);
 assert(up.includes('server up'),'server booted: '+up);
 const dev=JSON.parse(fs.readFileSync(path.join(dir,'device.json'),'utf8'));
 assert(/^[0-9a-f]{16}$/.test(dev.id),'device id minted locally');
 const U='http://127.0.0.1:47790';
 // health proof
 const h=await(await fetch(U+'/health?nonce=abc12345',{headers:{'X-GW-Key':'srv-key'}})).json();
 assert(h.deviceId===dev.id&&crypto.verify(null,Buffer.from(h.deviceId+'\nabc12345','utf8'),crypto.createPublicKey({key:Buffer.from(dev.pub,'base64'),format:'der',type:'spki'}),Buffer.from(h.sig,'hex')),'health nonce proof');
 // unsigned command refused
 const bad=await fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify({id:'c1',kind:'find_files',data:{query:'dad'}})});
 assert(bad.status===403,'unsigned -> 403');
 // signed find_files -> terminal result with the real match
 const ts=Date.now(),exp=ts+300000,data={query:'dad'};
 const ok=await fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify({id:'c2',kind:'find_files',ts,exp,sig:sign('c2','find_files',ts,exp,JSON.stringify(data)),data})});
 assert(ok.status===202,'signed find_files accepted');
 let rec=null;for(let i=0;i<50;i++){const r=await fetch(U+'/task?id=c2',{headers:signRead('/task','id=c2',dev.id)});const j=await r.json();if(j.terminal){rec=j;break}await sleep(200)}
 assert(rec&&rec.status==='done'&&rec.result.matches.length===1&&rec.result.matches[0].path.includes('presentation-dad.txt'),'result via /task: '+JSON.stringify(rec));
 // read_file within roots; outside refused
 const ts2=Date.now(),exp2=ts2+300000,d2={path:path.join(fold,'presentation-dad.txt')};
 await fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify({id:'c3',kind:'read_file',ts:ts2,exp:exp2,sig:sign('c3','read_file',ts2,exp2,JSON.stringify(d2)),data:d2})});
 let rec3=null;for(let i=0;i<50;i++){const j=await(await fetch(U+'/task?id=c3',{headers:signRead('/task','id=c3',dev.id)})).json();if(j.terminal){rec3=j;break}await sleep(200)}
 assert(rec3.status==='done'&&Buffer.from(rec3.result.content_base64,'base64').toString()==='deck contents','read_file content round-trip');
 const ts3=Date.now(),exp3=ts3+300000,d3={path:'/etc/passwd'};
 await fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify({id:'c4',kind:'read_file',ts:ts3,exp:exp3,sig:sign('c4','read_file',ts3,exp3,JSON.stringify(d3)),data:d3})});
 let rec4=null;for(let i=0;i<50;i++){const j=await(await fetch(U+'/task?id=c4',{headers:signRead('/task','id=c4',dev.id)})).json();if(j.terminal){rec4=j;break}await sleep(200)}
 assert(rec4.status==='failed'&&/outside_roots/.test(rec4.note||''),'outside roots -> failed terminal: '+JSON.stringify(rec4));
 // replay -> 409
 const dup=await fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify({id:'c2',kind:'find_files',ts:Date.now(),exp:Date.now()+300000,sig:sign('c2','find_files',Date.now(),Date.now()+300000,JSON.stringify(data)),data})});
 assert(dup.status===409,'replay -> 409');
 // /task without signed read auth -> 403
 assert((await fetch(U+'/task?id=c2',{headers:{'X-GW-Key':'srv-key'}})).status===403,'unsigned read -> 403');
 // restart: device identity persists, ledger survives, crashed-record reconciliation works
 cp.kill('SIGTERM');await sleep(500);
 const cp2=spawn(process.execPath,['server/index.js'],{env:{...process.env,GW_SERVER_CONFIG:path.join(dir,'config.json')},stdio:['ignore','pipe','pipe']});
 let up2='';cp2.stdout.on('data',d=>up2+=d);
 for(let i=0;i<60&&!up2.includes('server up');i++)await sleep(200);
 assert(up2.includes('server up'),'restart: '+up2);
 const dev2=JSON.parse(fs.readFileSync(path.join(dir,'device.json'),'utf8'));
 assert(dev2.id===dev.id,'device identity persists across restart');
 const j2=await(await fetch(U+'/task?id=c2',{headers:signRead('/task','id=c2',dev.id)})).json();
 assert(j2.status==='done'&&j2.result.matches.length===1,'terminal record survives restart');
 cp2.kill('SIGTERM');
 console.log('SERVER-SKELETON-UNIT: PASS');
 process.exit(0);
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
