// Skeleton smoke test: boot the standalone server, signed command -> durable result -> replay.
// Ephemeral port + finally cleanup: a failed assert never leaves a stray process behind.
const assert=require('assert'),fs=require('fs'),path=require('path'),crypto=require('crypto'),{spawn}=require('child_process');
const dir=fs.mkdtempSync('/tmp/gw-srv-');
const rootsBase=fs.mkdtempSync('/tmp/gw-roots-'); // roots OUTSIDE the server data dir - the data dir is denylisted (secrets never reachable via ops)
const fold=path.join(rootsBase,'files');fs.mkdirSync(fold);
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
const boot=(extra)=>{const cp=spawn(process.execPath,['server/index.js'],{env:{...process.env,GW_SERVER_CONFIG:path.join(dir,'config.json'),...(extra||{})},stdio:['ignore','pipe','pipe']});
 let out='',err='';cp.stdout.on('data',d=>out+=d);cp.stderr.on('data',d=>err+=d);return{cp,out:()=>out,err:()=>err}};
const waitUp=async(b,label)=>{for(let i=0;i<60&&!b.out().includes('server up');i++)await sleep(200);
 assert(b.out().includes('server up'),label+' booted: '+b.out()+' STDERR: '+b.err());
 return 'http://127.0.0.1:'+/server up on 127\.0\.0\.1:(\d+)/.exec(b.out())[1]};
const post=(U,body)=>fetch(U+'/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'srv-key'},body:JSON.stringify(body)});
const task=async(U,id,dev)=>{let j=null;for(let i=0;i<50;i++){j=await(await fetch(U+'/task?id='+id,{headers:signRead('/task','id='+id,dev)})).json();if(j.terminal)break;await sleep(200)}return j};
const kill=cp=>new Promise(res=>{if(!cp||cp.exitCode!==null)return res();cp.once('exit',()=>res());cp.kill('SIGTERM');setTimeout(res,3000).unref()});
let b1=null,b2=null,bS=null,b4=null,bE=null,dir2=null;
(async()=>{try{
 b1=boot();const U=await waitUp(b1,'server');
 const devJson=fs.readFileSync(path.join(dir,'device.json'),'utf8');
 const dev=JSON.parse(devJson);
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
 // --- stage-1: always-on denylist + write_file ---
 // the server's own data dir is denied even though it sits next to the roots
 ts=Date.now();exp=ts+300000;const dCfg={path:path.join(dir,'config.json')};
 await post(U,{id:'cC',kind:'read_file',ts,exp,sig:sign('cC','read_file',ts,exp,JSON.stringify(dCfg)),data:dCfg});
 const recC=await task(U,'cC',dev.id);
 assert(recC.status==='failed'&&/outside_roots/.test(recC.note||''),'server config unreadable via ops (data-dir deny): '+JSON.stringify(recC));
 // browser-credential basenames are denied anywhere under roots
 fs.writeFileSync(path.join(fold,'Login Data'),'secret');
 ts=Date.now();exp=ts+300000;const dLD={path:path.join(fold,'Login Data')};
 await post(U,{id:'cL',kind:'read_file',ts,exp,sig:sign('cL','read_file',ts,exp,JSON.stringify(dLD)),data:dLD});
 const recL=await task(U,'cL',dev.id);
 assert(recL.status==='failed'&&/outside_roots/.test(recL.note||''),'Login Data denied anywhere: '+JSON.stringify(recL));
 // ... and invisible to find_files
 ts=Date.now();exp=ts+300000;const dFindDeny={query:'login'};
 await post(U,{id:'cF',kind:'find_files',ts,exp,sig:sign('cF','find_files',ts,exp,JSON.stringify(dFindDeny)),data:dFindDeny});
 const recF=await task(U,'cF',dev.id);
 assert(recF.status==='done'&&recF.result.matches.length===0,'denied names invisible to find_files: '+JSON.stringify(recF));
 // write_file: create -> content on disk -> second create REFUSED (never overwrites) -> append
 ts=Date.now();exp=ts+300000;const dW1={path:path.join(fold,'written.txt'),content_base64:Buffer.from('hello pc').toString('base64')};
 await post(U,{id:'w1',kind:'write_file',ts,exp,sig:sign('w1','write_file',ts,exp,JSON.stringify(dW1)),data:dW1});
 const recW1=await task(U,'w1',dev.id);
 assert(recW1.status==='done'&&recW1.result.bytes===8&&recW1.result.mode==='create','write_file create: '+JSON.stringify(recW1));
 assert(fs.readFileSync(path.join(fold,'written.txt'),'utf8')==='hello pc','content landed on disk');
 ts=Date.now();exp=ts+300000;
 await post(U,{id:'w2',kind:'write_file',ts,exp,sig:sign('w2','write_file',ts,exp,JSON.stringify(dW1)),data:dW1});
 const recW2=await task(U,'w2',dev.id);
 assert(recW2.status==='failed'&&/exists/.test(recW2.note||''),'write_file NEVER overwrites: '+JSON.stringify(recW2));
 ts=Date.now();exp=ts+300000;const dW3={path:path.join(fold,'written.txt'),content_base64:Buffer.from(' again').toString('base64'),mode:'append'};
 await post(U,{id:'w3',kind:'write_file',ts,exp,sig:sign('w3','write_file',ts,exp,JSON.stringify(dW3)),data:dW3});
 const recW3=await task(U,'w3',dev.id);
 assert(recW3.status==='done'&&recW3.result.mode==='append','write_file append: '+JSON.stringify(recW3));
 assert(fs.readFileSync(path.join(fold,'written.txt'),'utf8')==='hello pc again','append landed');
 // write outside roots refused
 ts=Date.now();exp=ts+300000;const dW4={path:'/tmp/outside-gw.txt',content_base64:Buffer.from('x').toString('base64')};
 await post(U,{id:'w4',kind:'write_file',ts,exp,sig:sign('w4','write_file',ts,exp,JSON.stringify(dW4)),data:dW4});
 const recW4=await task(U,'w4',dev.id);
 assert(recW4.status==='failed'&&/outside_roots/.test(recW4.note||''),'write outside roots refused: '+JSON.stringify(recW4));
 // --- stage-2: sys_info + run_command + open_path ---
 ts=Date.now();exp=ts+300000;
 await post(U,{id:'i1',kind:'sys_info',ts,exp,sig:sign('i1','sys_info',ts,exp,'{}'),data:{}});
 const recI=await task(U,'i1',dev.id);
 assert(recI.status==='done'&&recI.result.hostname&&recI.result.cpus>=1,'sys_info: '+JSON.stringify(recI).slice(0,200));
 // run_command wait: args array (no shell), captured stdout, exit code
 ts=Date.now();exp=ts+300000;const dR1={exe:process.execPath,args:['-e','console.log("marker-"+21*2)']};
 await post(U,{id:'r1',kind:'run_command',ts,exp,sig:sign('r1','run_command',ts,exp,JSON.stringify(dR1)),data:dR1});
 const recR1=await task(U,'r1',dev.id);
 assert(recR1.status==='done'&&recR1.result.exitCode===0&&recR1.result.stdout.trim()==='marker-42','run_command wait: '+JSON.stringify(recR1).slice(0,250));
 // missing exe -> loud failure, never a hang
 ts=Date.now();exp=ts+300000;const dR2={exe:'definitely-not-a-real-exe-xyz',args:[]};
 await post(U,{id:'r2',kind:'run_command',ts,exp,sig:sign('r2','run_command',ts,exp,JSON.stringify(dR2)),data:dR2});
 const recR2=await task(U,'r2',dev.id);
 assert(recR2.status==='failed'&&/spawn_failed/.test(recR2.note||''),'bad exe -> failed: '+JSON.stringify(recR2));
 // cwd outside roots refused
 ts=Date.now();exp=ts+300000;const dR3={exe:process.execPath,args:['-e','1'],cwd:'/etc'};
 await post(U,{id:'r3',kind:'run_command',ts,exp,sig:sign('r3','run_command',ts,exp,JSON.stringify(dR3)),data:dR3});
 const recR3=await task(U,'r3',dev.id);
 assert(recR3.status==='failed'&&/outside_roots/.test(recR3.note||''),'cwd outside roots refused: '+JSON.stringify(recR3));
 // detached: started with a pid, no waiting
 ts=Date.now();exp=ts+300000;const dR4={exe:process.execPath,args:['-e','setTimeout(()=>{},200)'],wait:false};
 await post(U,{id:'r4',kind:'run_command',ts,exp,sig:sign('r4','run_command',ts,exp,JSON.stringify(dR4)),data:dR4});
 const recR4=await task(U,'r4',dev.id);
 assert(recR4.status==='done'&&recR4.result.started===true&&recR4.result.pid>0,'detached start: '+JSON.stringify(recR4));
 // open_path outside roots refused; a URL opens (detached, no assertion on the app)
 ts=Date.now();exp=ts+300000;const dO1={path:'/etc/hostname'};
 await post(U,{id:'o1',kind:'open_path',ts,exp,sig:sign('o1','open_path',ts,exp,JSON.stringify(dO1)),data:dO1});
 const recO1=await task(U,'o1',dev.id);
 assert(recO1.status==='failed'&&/outside_roots/.test(recO1.note||''),'open outside roots refused: '+JSON.stringify(recO1));
 ts=Date.now();exp=ts+300000;const dO2={path:path.join(fold,'presentation-dad.txt')};
 await post(U,{id:'o2',kind:'open_path',ts,exp,sig:sign('o2','open_path',ts,exp,JSON.stringify(dO2)),data:dO2});
 const recO2=await task(U,'o2',dev.id);
 assert(recO2.status==='done','open under roots: '+JSON.stringify(recO2));
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
 const bad=JSON.parse(devJson);bad.pub=bad.pub.split('').reverse().join('');
 fs.writeFileSync(path.join(dir,'device.json'),JSON.stringify(bad));
 const b3=boot();let dead=false;b3.cp.once('exit',()=>dead=true);
 for(let i=0;i<40&&!dead;i++)await sleep(200);
 assert(dead&&!b3.out().includes('server up'),'corrupt device file -> boot refused (no silent identity renew): '+b3.out());
 await kill(b3.cp);
 fs.writeFileSync(path.join(dir,'device.json'),devJson); // restore the valid identity
 // strict envelopes opt-in (mirrors the agent's STRICT_ENVELOPES): v1 -> 403 device_required, v2 device-bound -> 202
 bS=boot({GW_SERVER_STRICT_ENVELOPES:'1'});const US=await waitUp(bS,'strict');
 ts=Date.now();exp=ts+300000;const dV={query:'dad'};
 assert((await post(US,{id:'s1',kind:'find_files',ts,exp,sig:sign('s1','find_files',ts,exp,JSON.stringify(dV)),data:dV})).status===403,'strict: v1 -> 403 device_required');
 const sigV=crypto.sign(null,Buffer.from([dev.id,'s2','find_files',String(ts),String(exp),JSON.stringify(dV)].join('\n'),'utf8'),PRIV).toString('hex');
 assert((await post(US,{id:'s2',kind:'find_files',device:dev.id,ts,exp,sig:sigV,data:dV})).status===202,'strict: v2 device-bound accepted');
 await kill(bS.cp);bS=null;
 // unreadable (non-ENOENT) device path: fail CLOSED, never minted over
 fs.rmSync(path.join(dir,'device.json'));fs.mkdirSync(path.join(dir,'device.json'));
 b4=boot();let dead4=false;b4.cp.once('exit',()=>dead4=true);
 for(let i=0;i<40&&!dead4;i++)await sleep(200);
 assert(dead4&&!b4.out().includes('server up'),'unreadable device path -> fail closed, no mint-over: '+b4.out());
 await kill(b4.cp);b4=null;
 // env-only first boot on a FRESH data dir (no config file at all): private dir created, then mint
 dir2=fs.mkdtempSync('/tmp/gw-srv-env-');const fresh=path.join(dir2,'fresh'); // does NOT exist yet
 bE=boot({GW_SERVER_CONFIG:path.join(fresh,'config.json'),GW_SERVER_TOKEN:'srv-key',GW_SENDER_PUB:PUB_B64});
 await waitUp(bE,'env-only');
 assert(fs.existsSync(path.join(fresh,'device.json')),'env-only: device minted in the fresh dir');
 assert((fs.statSync(fresh).mode&511)===448,'fresh dir created private (700): '+(fs.statSync(fresh).mode&511).toString(8));
 await kill(bE.cp);bE=null;
 console.log('SERVER-SKELETON-UNIT: PASS');
}catch(e){console.error('FAIL',e);process.exitCode=1}
finally{for(const b of [b1,b2,bS,b4,bE])await kill(b&&b.cp);
 try{fs.rmSync(dir,{recursive:true,force:true})}catch(e){console.error('cleanup failed:',e.message)}
 try{fs.rmSync(rootsBase,{recursive:true,force:true})}catch(e){console.error('cleanup-roots failed:',e.message)}
 if(dir2)try{fs.rmSync(dir2,{recursive:true,force:true})}catch(e){console.error('cleanup2 failed:',e.message)}
 process.exit(process.exitCode||0)}})();
