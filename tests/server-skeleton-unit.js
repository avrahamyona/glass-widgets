// Skeleton smoke test: boot the standalone server, signed command -> durable result -> replay.
// Ephemeral port + finally cleanup: a failed assert never leaves a stray process behind.
const assert=require('assert'),fs=require('fs'),path=require('path'),crypto=require('crypto'),{spawn}=require('child_process');
const dir=fs.mkdtempSync('/tmp/gw-srv-');
const fold=path.join(dir,'files');fs.mkdirSync(fold);
fs.writeFileSync(path.join(fold,'presentation-dad.txt'),'deck contents');
fs.writeFileSync(path.join(fold,'big.txt'),'x'.repeat(5000)); // over the 1KB inline cap
const sub=path.join(fold,'sub');fs.mkdirSync(sub);fs.writeFileSync(path.join(sub,'inner-dad.txt'),'inner');
const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const PUB_B64=PUB.export({format:'der',type:'spki'}).toString('base64');
fs.writeFileSync(path.join(dir,'config.json'),JSON.stringify({token:'srv-key',senderPub:PUB_B64,port:0,roots:[fold]}));
const sign=(id,kind,ts,exp,payload)=>crypto.sign(null,Buffer.from([id,kind,String(ts),String(exp),payload].join('\n'),'utf8'),PRIV).toString('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const signRead=(p,q,dev)=>{const ts=Date.now(),nonce=crypto.randomBytes(12).toString('base64url');
 return{'X-GW-Key':'srv-key','X-GW-Read-Ts':String(ts),'X-GW-Read-Nonce':nonce,'X-GW-Read-Device':dev,
 'X-GW-Read-Sig':crypto.sign(null,Buffer.from(['GET',p,q,String(ts),nonce,dev].join('\n'),'utf8'),PRIV).toString('hex')}};
const boot=()=>{const cp=spawn(process.execPath,['server/index.js'],{env:{...process.env,GW_SERVER_CONFIG:path.join(dir,'config.json')},stdio:['ignore','pipe','pipe']});
 let out='',err='';cp.stdout.on('data',d=>out+=d);cp.stderr.on('data',d=>err+=d);return{cp,out:()=>out,err:()=>err}};
const waitUp=async(b,label)=>{for(let i=0;i<60&&!b.out().includes('server up');i++)await sleep(200);
 assert(b.out().includes('server up'),label+' booted: '+b.out()+' STDERR: '+b.err());
 return 'http://127.0.0.1:'+/server up on 127\.0\.0\.1:(\d+)/.exec(b.out())[1]};
const post=(U,body)=>fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify(body)});
const task=async(U,id,dev)=>{let j=null;for(let i=0;i<50;i++){j=await(await fetch(U+'/task?id='+id,{headers:signRead('/task','id='+id,dev)})).json();if(j.terminal)break;await sleep(200)}return j};
const kill=cp=>new Promise(res=>{if(!cp||cp.exitCode!==null)return res();cp.once('exit',()=>res());cp.kill('SIGTERM');setTimeout(res,3000).unref()});
let b1=null,b2=null;
(async()=>{try{
 b1=boot();const U=await waitUp(b1,'server');
 const dev=JSON.parse(fs.readFileSync(path.join(dir,'device.json'),'utf8'));
 assert(/^[0-9a-f]{16}$/.test(dev.id),'device id minted locally');
 assert(dev.priv&&dev.pub,'device keypair persisted');
 // health proof
 const h=await(await fetch(U+'/health?nonce=abc12345',{headers:{'X-GW-Key':'srv-key'}})).json();
 assert(h.deviceId===dev.id&&crypto.verify(null,Buffer.from(h.deviceId+'\nabc12345','utf8'),crypto.createPublicKey({key:Buffer.from(dev.pub,'base64'),format:'der',type:'spki'}),Buffer.from(h.sig,'hex')),'health nonce proof');
 // unsigned command refused
 assert((await post(U,{id:'c1',kind:'find_files',data:{query:'dad'}})).status===403,'unsigned -> 403');
 // prototype kind names are NOT ops
 assert((await post(U,{id:'cP',kind:'constructor',ts:Date.now(),exp:Date.now()+60000,sig:'0'.repeat(128),data:{}})).status===400,'prototype kind -> 400 unknown_kind');
 // signed find_files -> terminal result with the real match
 let ts=Date.now(),exp=ts+300000,data={query:'dad'};
 assert((await post(U,{id:'c2',kind:'find_files',ts,exp,sig:sign('c2','find_files',ts,exp,JSON.stringify(data)),data})).status===202,'signed find_files accepted');
 const rec=await task(U,'c2',dev.id);
 assert(rec&&rec.status==='done'&&rec.result.matches.length===2,'result via /task: '+JSON.stringify(rec&&rec.result));
 // roots NARROWING: a sender subdir under a configured root scans there only
 ts=Date.now();exp=ts+300000;const dN={query:'dad',roots:[sub,'/etc']}; // '/etc' must be dropped by the narrowing filter
 assert((await post(U,{id:'cN',kind:'find_files',ts,exp,sig:sign('cN','find_files',ts,exp,JSON.stringify(dN)),data:dN})).status===202,'narrowed find accepted');
 const recN=await task(U,'cN',dev.id);
 assert(recN.status==='done'&&recN.result.matches.length===1&&recN.result.matches[0].path.includes('inner-dad.txt'),'narrowing scans the subdir only: '+JSON.stringify(recN.result));
 // roots WIDENING: only out-of-root dirs -> failed outside_roots
 ts=Date.now();exp=ts+300000;const dW={query:'dad',roots:['/etc']};
 assert((await post(U,{id:'cW',kind:'find_files',ts,exp,sig:sign('cW','find_files',ts,exp,JSON.stringify(dW)),data:dW})).status===202,'widening attempt accepted for dispatch');
 const recW=await task(U,'cW',dev.id);
 assert(recW.status==='failed'&&/outside_roots/.test(recW.note||''),'widening refused: '+JSON.stringify(recW));
 // read_file within roots: small file round-trips
 ts=Date.now();exp=ts+300000;const d2={path:path.join(fold,'presentation-dad.txt')};
 await post(U,{id:'c3',kind:'read_file',ts,exp,sig:sign('c3','read_file',ts,exp,JSON.stringify(d2)),data:d2});
 const rec3=await task(U,'c3',dev.id);
 assert(rec3.status==='done'&&rec3.result.truncated===false&&Buffer.from(rec3.result.content_base64,'base64').toString()==='deck contents','small read_file round-trip');
 // read_file over the inline cap: EXPLICIT truncation, never a silent metadata-only
 ts=Date.now();exp=ts+300000;const dB={path:path.join(fold,'big.txt')};
 await post(U,{id:'cB',kind:'read_file',ts,exp,sig:sign('cB','read_file',ts,exp,JSON.stringify(dB)),data:dB});
 const recB=await task(U,'cB',dev.id);
 assert(recB.status==='done'&&recB.result.truncated===true&&recB.result.inline_cap===1024&&recB.result.size===5000,'explicit truncation: '+JSON.stringify(recB.result&&{t:recB.result.truncated,c:recB.result.inline_cap,s:recB.result.size}));
 // outside roots refused
 ts=Date.now();exp=ts+300000;const d3={path:'/etc/passwd'};
 await post(U,{id:'c4',kind:'read_file',ts,exp,sig:sign('c4','read_file',ts,exp,JSON.stringify(d3)),data:d3});
 const rec4=await task(U,'c4',dev.id);
 assert(rec4.status==='failed'&&/outside_roots/.test(rec4.note||''),'outside roots -> failed terminal');
 // replay -> 409
 ts=Date.now();exp=ts+300000;
 assert((await post(U,{id:'c2',kind:'find_files',ts,exp,sig:sign('c2','find_files',ts,exp,JSON.stringify(data)),data})).status===409,'replay -> 409');
 // /task without signed read auth -> 403
 assert((await fetch(U+'/task?id=c2',{headers:{'X-GW-Key':'srv-key'}})).status===403,'unsigned read -> 403');
 // restart: device identity persists, ledger survives
 await kill(b1.cp);b1=null;
 b2=boot();await waitUp(b2,'restart');
 const dev2=JSON.parse(fs.readFileSync(path.join(dir,'device.json'),'utf8'));
 assert(dev2.id===dev.id,'device identity persists across restart');
 const j2=await(await fetch(U+'/task?id=c2',{headers:signRead('/task','id=c2',dev.id)})).json();
 assert(j2.status==='done'&&j2.result.matches.length===2,'terminal record survives restart');
 await kill(b2.cp);b2=null;
 // corrupt device file: boot fails LOUD, identity never silently renews
 const bad=JSON.parse(fs.readFileSync(path.join(dir,'device.json'),'utf8'));bad.pub=bad.pub.split('').reverse().join('');
 fs.writeFileSync(path.join(dir,'device.json'),JSON.stringify(bad));
 const b3=boot();let dead=false;b3.cp.once('exit',()=>dead=true);
 for(let i=0;i<40&&!dead;i++)await sleep(200);
 assert(dead&&!b3.out().includes('server up'),'corrupt device file -> boot refused (no silent identity renew): '+b3.out());
 await kill(b3.cp);
 console.log('SERVER-SKELETON-UNIT: PASS');
}catch(e){console.error('FAIL',e);process.exitCode=1}
finally{await kill(b1&&b1.cp);await kill(b2&&b2.cp);
 try{fs.rmSync(dir,{recursive:true,force:true})}catch(e){console.error('cleanup failed:',e.message)}
 process.exit(process.exitCode||0)}})();
