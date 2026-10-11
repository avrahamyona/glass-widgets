const REPO=process.env.GW_REPO||'/home/sandbox/glass-widgets';
const {_electron:e}=require(REPO+'/node_modules/playwright');const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),crypto=require('crypto');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const {publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const PUB_B64=PUB.export({format:'der',type:'spki'}).toString('base64');
const sign=(id,kind,ts,exp,payload)=>crypto.sign(null,Buffer.from([id,kind,String(ts),String(exp),payload].join('\n'),'utf8'),PRIV).toString('hex');
let ACK=[],CMDQS=[];
const srv=http.createServer((q,r)=>{const u=new URL(q.url,'http://x');
 if(u.pathname==='/chat/stream'){r.writeHead(200,{'content-type':'text/event-stream'});r.write(': ready\n\n');return}
 if(u.pathname==='/chat'&&q.method==='GET'){r.writeHead(200,{'content-type':'application/json'});r.end('{"ok":true,"read_upto":0,"messages":[]}');return}
 if(u.pathname==='/chat'&&q.method==='POST'){let b='';q.on('data',d=>b+=d);q.on('end',()=>{r.writeHead(200,{'content-type':'application/json'});r.end('{"ok":true,"id":"x1"}')});return}
 if(u.pathname==='/chat/action'&&q.method==='POST'){r.writeHead(200,{'content-type':'application/json'});r.end('{"ok":true}');return}
 if(u.pathname==='/cmd/stream'){CMDQS.push(u.search);r.writeHead(200,{'content-type':'text/event-stream'});r.write(': ready\n\n');global.cmdRes=r;return}
 if(u.pathname==='/cmd/ack'){let b='';q.on('data',d=>b+=d);q.on('end',()=>{ACK.push(JSON.parse(b||'{}'));r.end('{}')});return}
 if(u.pathname==='/web'){r.writeHead(200,{'content-type':'text/html'});r.end('<html><body>webtask-ok</body></html>');return}
 r.statusCode=404;r.end()});
const pushCmd=m=>{if(global.cmdRes)global.cmdRes.write('data: '+JSON.stringify(m)+'\n\n')};
const M=n=>path.join(os.tmpdir(),'gw-sig-'+n+'-'+Date.now()+'.txt');
const m1=M(1),m2=M(2),m3=M(3),m4=M(4),m5=M(5),m6=M(6),m7=M(7),m8=M(8);
const EX=()=>Date.now()+300000;
const waitAck=async(id,status)=>{for(let i=0;i<40;i++){const a=ACK.find(x=>x.id===id&&x.status===status);if(a)return a;await sleep(200)}throw new Error('no ack '+id+' '+status+' in '+JSON.stringify(ACK.slice(-6)))};
let env,cfg,port;
const launch=async()=>{
 const old=global.cmdRes;
 const a=await e.launch({executablePath:REPO+'/node_modules/electron/dist/electron',args:['--no-sandbox',REPO],env});
 const waitWin=async pat=>{for(let i=0;i<80;i++){const w=a.windows().find(w=>w.url().includes(pat));if(w)return w;await sleep(150)}throw new Error('no '+pat)};
 const A=await waitWin('/chat/');await sleep(1500);
 for(let i=0;i<120&&global.cmdRes===old;i++)await sleep(250);
 assert(global.cmdRes&&global.cmdRes!==old,'agent connected');
 return {a,A};
};
(async()=>{
 await new Promise(r=>srv.listen(0,'127.0.0.1',r));port=srv.address().port;
 cfg=fs.mkdtempSync('/tmp/gw-sig-');fs.mkdirSync(cfg+'/glasswidgets',{recursive:true});
 fs.writeFileSync(cfg+'/glasswidgets/instances.json',JSON.stringify([{id:'chat',type:'chat'}]));
 fs.writeFileSync(cfg+'/glasswidgets/settings.json',JSON.stringify({instanceConfigs:{chat:{size:'island'}}}));
 env={...process.env,XDG_CONFIG_HOME:cfg,GLASSWIDGETS_NO_PICKER:'1',PYTHONPATH:'/tmp/pystub',GLASSWIDGETS_CLOUD_PYTHON:'/usr/bin/python3',
  GLASSWIDGETS_CHAT_URL:'http://127.0.0.1:'+port+'/chat',GLASSWIDGETS_CHAT_STREAM_URL:'http://127.0.0.1:'+port+'/chat/stream',
  GLASSWIDGETS_CHAT_KEY:'chat-key',GLASSWIDGETS_AGENT_CMD_KEY:'cmd-key',GLASSWIDGETS_AGENT_CMD_URL:'http://127.0.0.1:'+port+'/cmd/stream',GLASSWIDGETS_AGENT_ACK_URL:'http://127.0.0.1:'+port+'/cmd/ack',
  GLASSWIDGETS_APPROVAL_TTL_MS:'4000',GLASSWIDGETS_AUTO_RUN_MS:'2500',GLASSWIDGETS_AGENT_SIGN_PUB:PUB_B64,GLASSWIDGETS_WEB_TASK_ALLOW_LOCAL:'1',GLASSWIDGETS_LOCAL_SERVER_PORT:'47732',GLASSWIDGETS_TUNNEL_ENABLED:'0'};
 global.cmdRes=null;
 let {a,A}=await launch();
 assert(CMDQS[0].includes('sig'),'caps advertises sig: '+CMDQS[0]);
 const card=async find=>{for(let i=0;i<40;i++){const c=await A.evaluate(f=>{const els=[...document.querySelectorAll('#pillBody .card')];const el=els.find(e=>e.textContent.includes(f));return el?{cid:el.dataset.cid,title:el.querySelector('.ct').textContent,body:el.querySelector('.cb')?el.querySelector('.cb').textContent:'',btns:[...el.querySelectorAll('button')].map(b=>b.textContent)}:null},find);if(c)return c;await sleep(200)}throw new Error('no card matching '+find)};
 const clickBtn=(find,label)=>A.evaluate(([f,l])=>{const el=[...document.querySelectorAll('#pillBody .card')].find(e=>e.textContent.includes(f));const b=[...el.querySelectorAll('button')].find(b=>b.textContent===l);if(b)b.click()},[find,label]);
 // 1) signed run_command: informational card, auto-executes with NO tap
 let ts=Date.now(),exp=EX();pushCmd({id:'s1',kind:'run_command',command:'touch '+m1,ts,exp,sig:sign('s1','run_command',ts,exp,'touch '+m1)});
 let c=await card('touch '+m1);
 assert(/⚡ מבצע פקודה שאישרת/.test(c.title),'auto card title: '+c.title);
 assert.deepEqual(c.btns,['בטל'],'only cancel button: '+c.btns);
 for(let i=0;i<40&&!fs.existsSync(m1);i++)await sleep(200);
 assert(fs.existsSync(m1),'signed command auto-executed without a tap');
 await waitAck('s1','done');
 // 1b) replay in-session: the SAME signed message again -> duplicate refusal
 ACK=ACK.filter(x=>x.id!=='s1');pushCmd({id:'s1',kind:'run_command',command:'touch '+m1,ts,exp,sig:sign('s1','run_command',ts,exp,'touch '+m1)});
 let aR=null;for(let i=0;i<50;i++){aR=ACK.find(x=>x.id==='s1');if(aR)break;await sleep(200)}
 assert(aR&&aR.status==='done'&&aR.note==='ok','terminal replay re-acks the CACHED result (idempotent, no re-run): '+JSON.stringify(aR));
 const seen=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/agent-seen.json','utf8'));
 assert(seen.s1&&seen.s1.decision==='executed'&&seen.s1.exp===exp,'seen store persisted decision+exp: '+JSON.stringify(seen.s1));
 // 1c) replay after RESTART: relaunch with the same profile, same signed message -> still duplicate
 await a.close();
 ({a,A}=await launch());
 ACK=ACK.filter(x=>x.id!=='s1');
 pushCmd({id:'s1',kind:'run_command',command:'touch '+m1,ts,exp,sig:sign('s1','run_command',ts,exp,'touch '+m1)});
 let aR2=null;for(let i=0;i<50;i++){aR2=ACK.find(x=>x.id==='s1');if(aR2)break;await sleep(200)}
 assert(aR2&&aR2.status==='done'&&aR2.note==='ok','replay after restart: CACHED result re-acked from the durable ledger, no re-run: '+JSON.stringify(aR2));
 // 2) signed but cancelled in time: no execution, decision persisted
 ts=Date.now();exp=EX();pushCmd({id:'s2',kind:'run_command',command:'sleep 2 && touch '+m2,ts,exp,sig:sign('s2','run_command',ts,exp,'sleep 2 && touch '+m2)});
 c=await card('sleep 2 && touch '+m2);
 await clickBtn('sleep 2 && touch '+m2,'בטל');
 assert(/cancelled/.test((await waitAck('s2','failed')).note||''),'cancelled ack');
 await sleep(3000);assert(!fs.existsSync(m2),'cancelled command never executed');
 const seen2=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/agent-seen.json','utf8'));
 assert(seen2.s2&&seen2.s2.decision==='cancelled','cancel persisted');
 // 3) bad signature (valid shape, wrong key): BLOCKING card, no auto-run
 ts=Date.now();exp=EX();pushCmd({id:'s3',kind:'run_command',command:'touch '+m3,ts,exp,sig:'ab'.repeat(64)});
 c=await card('touch '+m3);
 assert(/אישור הרצת פקודה/.test(c.title),'bad sig -> blocking card: '+c.title);
 assert.deepEqual(c.btns,['אשר','דחה'],'blocking buttons: '+c.btns);
 // 3b) malformed signatures (unicode, short): no crash, blocking card too
 ts=Date.now();exp=EX();pushCmd({id:'s3b',kind:'run_command',command:'touch '+m3,ts,exp,sig:'אבגד'.repeat(32)});
 ts=Date.now();pushCmd({id:'s3c',kind:'run_command',command:'touch '+m3,ts,exp,sig:'ab'});
 await sleep(2500);assert(!fs.existsSync(m3),'bad/malformed sigs never auto-execute');
 await clickBtn('touch '+m3,'דחה');await clickBtn('touch '+m3,'דחה');await clickBtn('touch '+m3,'דחה');
 // 4) expired exp: blocking card
 ts=Date.now();exp=Date.now()-1000;pushCmd({id:'s4',kind:'run_command',command:'touch '+m4,ts,exp,sig:sign('s4','run_command',ts,exp,'touch '+m4)});
 const aS4=await waitAck('s4','failed'); // expired transport authority is refused at intake - no card, no user prompt
 assert(/expired/.test(aS4.note||''),'expired sig refused at intake: '+aS4.note);
 assert(!fs.existsSync(m4),'expired sig never executes');
 // 6) ts too far in the FUTURE: blocking card
 ts=Date.now()+120000;exp=ts+60000;pushCmd({id:'s6',kind:'run_command',command:'touch '+m5,ts,exp,sig:sign('s6','run_command',ts,exp,'touch '+m5)});
 c=await card('touch '+m5);
 assert(/אישור הרצת פקודה/.test(c.title),'future ts -> blocking card: '+c.title);
 await sleep(1500);assert(!fs.existsSync(m5),'future-ts never auto-executes');
 await clickBtn('touch '+m5,'דחה');
 // 7) exp<=ts: expired transport authority - refused at intake, no card
 ts=Date.now();exp=ts-1000;pushCmd({id:'s7',kind:'run_command',command:'touch '+m5,ts,exp,sig:sign('s7','run_command',ts,exp,'touch '+m5)});
 const aS7=await waitAck('s7','failed');
 assert(/expired/.test(aS7.note||''),'exp<=ts refused at intake: '+aS7.note);
 assert(!fs.existsSync(m5),'exp<=ts never executes');
 // 8) unsigned duplicate id: second push with a parked id refused, original card intact and approvable
 pushCmd({id:'s8',kind:'run_command',command:'touch '+m6});
 c=await card('touch '+m6);
 ACK=ACK.filter(x=>x.id!=='s8');
 pushCmd({id:'s8',kind:'run_command',command:'touch '+m5+'-evil'});
 await sleep(1200);assert(!ACK.some(x=>x.id==='s8'),'parked id: dup produces no ack');
 await clickBtn('touch '+m6,'אשר');
 for(let i=0;i<40&&!fs.existsSync(m6);i++)await sleep(200);
 assert(fs.existsSync(m6),'original parked command still executes on approve');
 assert(!fs.existsSync(m5+'-evil'),'replacement never ran');
 await waitAck('s8','done');
 // 8b) media_control carrying a parked signed run_command id is refused; the original auto-run still fires
 ts=Date.now();exp=EX();pushCmd({id:'s9',kind:'run_command',command:'sleep 1 && touch '+m7,ts,exp,sig:sign('s9','run_command',ts,exp,'sleep 1 && touch '+m7)});
 c=await card('sleep 1 && touch '+m7);
 ACK=ACK.filter(x=>x.id!=='s9');
 pushCmd({id:'s9',kind:'media_control',action:'toggle'});
 await sleep(1200);assert(!ACK.some(x=>x.id==='s9'),'media clobber: no ack');
 for(let i=0;i<40&&!fs.existsSync(m7);i++)await sleep(200);
 assert(fs.existsSync(m7),'original signed command still auto-ran');
 await waitAck('s9','done');
 await sleep(4500); // let any TTLs lapse before the slot test
 // 5b) signed web_task: the cancel card MUST be visible (regression: expiresAt referenced undefined m -> throw after park -> cardless auto-run)
 ts=Date.now();exp=EX();const wsteps=[{do:'extract',selector:'body'}];
 const wurl='http://127.0.0.1:'+port+'/web';
 pushCmd({id:'s5b',kind:'web_task',url:wurl,steps:wsteps,label:'בדיקת חתימה',ts,exp,sig:sign('s5b','web_task',ts,exp,wurl+'\n'+JSON.stringify(wsteps))});
 c=await card('משימת אתר שאישרת');
 assert(/⚡ מבצע משימת אתר שאישרת/.test(c.title),'signed web_task shows the auto card: '+c.title);
 assert.deepEqual(c.btns,['בטל'],'cancel path visible');
 const a5b=await waitAck('s5b','done');
 assert(a5b.result&&a5b.result.steps&&/webtask-ok/.test(a5b.result.steps[0].text||''),'web task ran and extracted: '+JSON.stringify(a5b.result));

 // 9)

 // 5) slot-order fix: oversized web_task plan rejected WITHOUT parking an invisible slot
 const bigSteps=Array.from({length:20},(_,i)=>({do:'type',selector:'#f'+i,text:'x'.repeat(48)}));
 pushCmd({id:'s5',kind:'web_task',url:'http://127.0.0.1:'+port+'/'+'a'.repeat(420),steps:bigSteps});
 assert(/card limit/.test((await waitAck('s5','failed')).note||''),'oversize rejected');
 for(let k=0;k<5;k++)pushCmd({id:'slot'+k,kind:'run_command',command:'echo slot'+k});
 await sleep(2500);
 const refusals=ACK.filter(x=>String(x.id).startsWith('slot')&&/too many/.test(x.note||''));
 assert.equal(refusals.length,0,'no phantom slot blocks later cards: '+JSON.stringify(refusals));
 for(let k=0;k<5;k++)await clickBtn('echo slot'+k,'דחה'); // free the five approval slots for the pairing section
 for(let k=0;k<5;k++)await waitAck('slot'+k,'failed');

 // 10) REAL enroll_device on the REAL agent runtime (vertical slice): challenge-bound identity
 // mint on this PC, durable device.json, narrow bootstrap read binding, local fingerprint source.
 const CH='chal-'+Date.now().toString(36)+'-abcdefgh';
 ts=Date.now();exp=EX();const ePay=JSON.stringify({challenge:CH});
 pushCmd({id:'enr1',kind:'enroll_device',data:{challenge:CH},ts,exp,sig:sign('enr1','enroll_device',ts,exp,ePay)});
 // PAIRING GATE: a signed enroll PARKS an on-PC approval card; nothing persists before the human tap
 const cP=await card('אישור צימוד טלפון');
 assert(cP.cid==='local-approve-enr1','pairing card bound to THIS command id: '+cP.cid);
 const cardFp=(cP.body.match(/[0-9a-f]{4}(-[0-9a-f]{4}){3}/)||[])[0];
 assert(cardFp,'pairing card shows the LOCAL candidate fingerprint: '+cP.body);
 assert(cP.body.includes('אשר רק אם יזמת צימוד'),'pairing card carries explicit compare-and-deny copy');
 assert(!fs.existsSync(cfg+'/glasswidgets/device/device.json'),'NO key persisted while the pairing card is parked');
 assert(fs.existsSync(cfg+'/glasswidgets/pairing-pending/enr1.json'),'durable per-id pairing-pending record exists while parked');
 await A.screenshot({path:'/downloads/pairing-card.png'}); // REAL UI pixels of the pairing card
 await clickBtn('אישור צימוד טלפון','אשר צימוד');
 const aE=await waitAck('enr1','done');
 assert(aE.result&&aE.result.deviceId&&aE.result.pubkey&&aE.result.challengeSig,'enroll returns identity+proof: '+JSON.stringify(aE.result));
 assert(aE.result.pairing&&aE.result.pairing.fingerprint===cardFp&&aE.result.pairing.cardId==='local-approve-enr1'&&aE.result.pairing.approvedAt>0,'the SAME approval (fingerprint+card+time) propagates to the registry-adapter terminal: '+JSON.stringify(aE.result.pairing));
 const devIdE=aE.result.deviceId,pubE=aE.result.pubkey;
 assert(devIdE===crypto.createHash('sha256').update(pubE).digest('hex').slice(0,16),'deviceId derives from the pubkey');
 assert(crypto.verify(null,Buffer.from([CH,pubE,devIdE].join('\n'),'utf8'),crypto.createPublicKey({key:Buffer.from(pubE,'base64'),format:'der',type:'spki'}),Buffer.from(aE.result.challengeSig,'hex')),'challenge proof verifies against the returned key');
 const devJ=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/device/device.json','utf8'));
 assert(devJ.pub===pubE&&devJ.priv&&crypto.createHash('sha256').update(devJ.pub).digest('hex').slice(0,16)===devIdE,'device identity persisted durably (pub+priv, id derives)');
 const{fingerprint:fpFn}=require(REPO+'/src/lib/fingerprint');
 const fpE=fpFn(pubE);
 assert(fpE===cardFp,'the card fingerprint is EXACTLY the minted key fingerprint (binding, not a generic approve)');
 // narrow bootstrap reads against the REAL local server (port 47732): exactly the pending command's /task under '-'
 const readHdr=(dev,path,q)=>{const rts=Date.now(),rn='n'+Math.random().toString(36).slice(2,10);const rs=crypto.sign(null,Buffer.from(['GET',path,q,String(rts),rn,dev].join('\n'),'utf8'),PRIV).toString('hex');return{'X-GW-Key':'cmd-key','X-GW-Read-Ts':String(rts),'X-GW-Read-Nonce':rn,'X-GW-Read-Sig':rs,'X-GW-Read-Device':dev}};
 const read=async(dev,path,q)=>{const r=await fetch('http://127.0.0.1:47732'+path+(q?'?'+q:''),{headers:readHdr(dev,path,q)});let b=null;try{b=await r.json()}catch{}return{status:r.status,body:b}};
 const rT=await read('-','/task','id=enr1');
 assert(rT.status===200&&rT.body.result&&rT.body.result.deviceId===devIdE,'bootstrap: pending enroll /task fetch under dash -> 200');
 assert((await read('-','/info','')).status===403,'bootstrap: /info under dash -> 403 (fail closed)');
 assert((await read('-','/task','id=nope')).status===403,'bootstrap: unrelated /task id under dash -> 403 (fail closed)');
 const rI=await read(devIdE,'/info','');
 assert(rI.status===200&&rI.body.fingerprint===fpE,'enrolled /info exposes the LOCAL fingerprint: '+JSON.stringify(rI.body));
 const auditTail=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(auditTail.includes('"stage":"enrolled"')&&auditTail.includes('"fingerprint":"'+fpE+'"'),'enroll audit carries the fingerprint');
 // malformed challenge parity: nested (SSE) and direct (local-server intake) BOTH refuse loudly
 ts=Date.now();exp=EX();pushCmd({id:'enrBad1',kind:'enroll_device',data:{challenge:123},ts,exp,sig:sign('enrBad1','enroll_device',ts,exp,JSON.stringify({challenge:123}))});
 assert((await waitAck('enrBad1','failed')).note==='bad challenge','nested malformed challenge refused (bad challenge)');
 ts=Date.now();exp=EX();const badPay=JSON.stringify({challenge:null});
 const dEnv={id:'enrBad2',kind:'enroll_device',data:{challenge:null},ts,exp,sig:sign('enrBad2','enroll_device',ts,exp,badPay)};
 const dRes=await fetch('http://127.0.0.1:47732/cmd',{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'cmd-key'},body:JSON.stringify(dEnv)});
 assert(dRes.status===202,'direct malformed enroll accepted for processing');
 assert((await waitAck('enrBad2','failed')).note==='bad challenge','direct-intake malformed challenge refused with the SAME explicit reason (no silent drop)');
 // a LONG NUMERIC challenge passes a String()-coerced shape check - refused by the typeof gate
 ts=Date.now();exp=EX();pushCmd({id:'enrBad3',kind:'enroll_device',data:{challenge:12345678},ts,exp,sig:sign('enrBad3','enroll_device',ts,exp,JSON.stringify({challenge:12345678}))});
 assert((await waitAck('enrBad3','failed')).note==='bad challenge','numeric challenge 12345678 refused (typeof gate, no String coercion)');

 // re-enroll (already enrolled): idempotent, fresh pending window for the NEW command id
 ts=Date.now();exp=EX();pushCmd({id:'enr2',kind:'enroll_device',data:{challenge:'re'+CH},ts,exp,sig:sign('enr2','enroll_device',ts,exp,JSON.stringify({challenge:'re'+CH}))});
 const aE2=await waitAck('enr2','done');
 assert(aE2.result.deviceId===devIdE&&aE2.result.pubkey===pubE,'re-enroll idempotent (same identity)');
 const rT2=await read('-','/task','id=enr2');
 assert(rT2.status===200,'re-enroll: the NEW command id fetches under dash');
 assert((await read('-','/task','id=enr1')).status===403,'re-enroll: the OLD command id no longer passes under dash');

 // 11) INTEGRATED fixture: the REAL sender client + REAL orchestrator against THIS live Electron
 // process, with independent X-GW-Device-Sig verification and unknown/same-id reconciliation.
 const{createSenderClient}=require(REPO+'/server/lib/sender-client.js');
 const{createEnrollOrchestrator}=require(REPO+'/server/lib/enroll-orchestrator.js');
 const{handleTunnel}=require(REPO+'/worker/tunnel-route.js');
 class FStmt{constructor(db,sql,args){this.db=db;this.sql=sql;this.args=args}
  async first(){const d=this.db,s=this.sql,a=this.args;
   if(s.includes('SELECT pubkey FROM devices')){const pk=d.devices.get(a[0]);return pk?{pubkey:pk.pubkey}:null}
   throw new Error('unexpected first: '+s)}
  async run(){const d=this.db,s=this.sql,a=this.args;
   if(s.startsWith('INSERT INTO devices')&&s.includes('WHERE (SELECT COUNT(*)')){
    if(d.devices.size>=a[3])return{meta:{changes:0}};
    d.devices.set(a[0],{pubkey:a[1],enrolled_at:a[2]});return{meta:{changes:1}}}
   throw new Error('unexpected run: '+s)}}
 class FDB{constructor(){this.devices=new Map()}
  prepare(sql){const db=this;return{bind(...args){return new FStmt(db,sql,args)}}}}
 const fdb=new FDB(),wEnv={AVI_ACCOUNT_DB:fdb,GW_REPLY_KEY:'rk-test',GW_MAX_DEVICES:'3'};
 const ctl=http.createServer(async(q,r)=>{let b='';q.on('data',c=>b+=c);q.on('end',async()=>{
  const u='http://w'+q.url;const wreq=new Request(u,{method:q.method,headers:{'X-GW-Reply-Key':String(q.headers['x-gw-reply-key']||''),'content-type':'application/json'},body:q.method==='POST'?b:undefined});
  const wres=await handleTunnel(wreq,wEnv,new URL(u));r.writeHead(wres.status,{'content-type':'text/plain'});r.end(await wres.text())})});
 await new Promise(r=>ctl.listen(0,'127.0.0.1',r));
 const SIGN_PRIV_B64=PRIV.export({format:'der',type:'pkcs8'}).toString('base64');
 // the pairing approval binds to the PC-LOCAL fingerprint source (the device.json on THIS machine) - never to the remote answer alone
 const devFpLocal=fpFn(JSON.parse(fs.readFileSync(cfg+'/glasswidgets/device/device.json','utf8')).pub);
 const memBox=()=>{const m=new Map();return{get:async id=>m.get(id)||null,put:async(id,r)=>{m.set(id,r);return true}}}; // in-memory outbox (per-sender, within the run only - durability is covered by fileBox below)
 const mkS=()=>createSenderClient({deviceUrl:'http://127.0.0.1:47732',controlUrl:'http://127.0.0.1:'+ctl.address().port,replyKey:'rk-test',cmdKey:'cmd-key',signPrivate:SIGN_PRIV_B64,preEnroll:true,fetchImpl:fetch,outbox:memBox(),pollIntervalMs:50});
 const orchLive=createEnrollOrchestrator({sender:mkS(),approvePairing:async({fingerprint,episode,challenge})=>fingerprint===devFpLocal&&!!episode&&!!challenge});
 const rO=await orchLive.run();
 assert(rO.ok===true&&rO.deviceId===devIdE,'integrated orchestrator enrolled against the LIVE Electron runtime: '+JSON.stringify(rO));
 assert(fdb.devices.get(devIdE)&&fdb.devices.get(devIdE).pubkey===pubE,'registry recorded the live device');
 const orchNo=createEnrollOrchestrator({sender:mkS(),approvePairing:async()=>false});
 const rNo=await orchNo.run();
 assert(rNo.ok===false&&rNo.stage==='pairing'&&fdb.devices.size===1,'declined pairing writes nothing in the REAL flow');
 const wrongK=crypto.generateKeyPairSync('ed25519');
 const wrongFp=fpFn(wrongK.publicKey.export({format:'der',type:'spki'}).toString('base64'));
 const orchWrongK=createEnrollOrchestrator({sender:mkS(),approvePairing:async({fingerprint})=>fingerprint===wrongFp}); // bound to a DIFFERENT (valid but wrong) key
 const rWK=await orchWrongK.run();
 assert(rWK.ok===false&&rWK.stage==='pairing'&&fdb.devices.size===1,'approval bound to a wrong-but-valid key refuses THIS pc in the REAL flow, nothing written');
 // independent X-GW-Device-Sig verification on a live /task response (not via the sender client)
 const rts=Date.now(),rnonce='n'+Math.random().toString(36).slice(2,10);
 const rsig=crypto.sign(null,Buffer.from(['GET','/task','id=enr2',String(rts),rnonce,devIdE].join('\n'),'utf8'),PRIV).toString('hex');
 const rH=await fetch('http://127.0.0.1:47732/task?id=enr2',{headers:{'X-GW-Key':'cmd-key','X-GW-Read-Ts':String(rts),'X-GW-Read-Nonce':rnonce,'X-GW-Read-Sig':rsig,'X-GW-Read-Device':devIdE}});
 const rawBody=await rH.text();
 const dSig=rH.headers.get('x-gw-device-sig'),dDev=rH.headers.get('x-gw-device');
 assert(dDev===devIdE&&/^[0-9a-f]{128}$/.test(String(dSig||'')),'device-signed response headers present');
 const bh=crypto.createHash('sha256').update(rawBody,'utf8').digest('hex');
 assert(crypto.verify(null,Buffer.from([devIdE,'GET','/task','id=enr2',String(rts),rnonce,String(rH.status),bh].join('\n'),'utf8'),crypto.createPublicKey({key:Buffer.from(pubE,'base64'),format:'der',type:'spki'}),Buffer.from(dSig,'hex')),'X-GW-Device-Sig verifies INDEPENDENTLY against the enrolled pubkey');
 // unknown/same-id retry reconciliation: ONE stored record, resent after a sender restart from a
 // DURABLE (file) outbox - byte-identical on the wire; lost-POST-after-accept reconciles as
 // duplicate; 404 -> unknown; expiry never hits the wire.
 const outDir=fs.mkdtempSync('/tmp/gw-outbox-');
 const{createFileOutbox}=require(REPO+'/server/lib/outbox-file.js');
 let liveBox=null;
 const fileBox=()=>{if(liveBox)liveBox.close();liveBox=createFileOutbox(outDir);return liveBox}; // the PRODUCTION durable outbox (atomic, fail-closed) - a sender restart closes then re-opens the same store
 const wireSeen=[];
 const rec=http.createServer((q,r)=>{if(q.url==='/cmd'&&q.method==='POST'){let b='';q.on('data',c=>b+=c);q.on('end',()=>{wireSeen.push(b);if(wireSeen.length===1){q.socket.destroy()}else{r.writeHead(409,{'content-type':'application/json'});r.end('{"ok":false,"reason":"duplicate","outcome":{"status":"accepted"}}')}})}else{r.writeHead(404);r.end()}}); // first POST: accepted then the response is LOST (socket dies); retry: 409 cached
 await new Promise(r=>rec.listen(0,'127.0.0.1',r));
 const mkRec=()=>createSenderClient({deviceUrl:'http://127.0.0.1:'+rec.address().port,controlUrl:'http://127.0.0.1:'+ctl.address().port,replyKey:'rk-test',cmdKey:'cmd-key',signPrivate:SIGN_PRIV_B64,preEnroll:true,fetchImpl:fetch,outbox:fileBox(),pollIntervalMs:50});
 const sA=mkRec();
 const p1=await sA.prepare({kind:'enroll_device',data:{challenge:'wire-'+Date.now().toString(36)}});
 const u1=await sA.send(p1);
 assert(u1.status==='unknown'&&u1.id,'lost POST after acceptance -> unknown (reconcile manually), never a claim: '+JSON.stringify(u1));
 const sB=mkRec(); // sender RESTART over the SAME durable outbox
 const u2=await sB.send({id:u1.id});
 assert(u2.id===u1.id,'retry keeps the SAME id');
 assert(wireSeen.length===2&&wireSeen[0]===wireSeen[1],'retry sends BYTE-IDENTICAL envelopes (the stored one)');
 assert(u2.status==='duplicate','accepted-then-lost reconciles as duplicate (cached outcome), never a re-run');
 const n1=await sB.pollTask('no-such-task-1');
 assert(n1.status==='unknown'&&n1.reason==='not_found'&&n1.id==='no-such-task-1','404 -> unknown not_found, same id');
 const pX=await sB.prepare({kind:'enroll_device',data:{challenge:'exp-'+Date.now().toString(36)},ttlMs:1000});
 await sleep(1100);
 const wireBefore=wireSeen.length;
 assert((await sB.send(pX)).status==='expired','an expired envelope never hits the wire');
 assert(wireSeen.length===wireBefore,'expired: NO wire call left the sender (wireSeen unchanged)');
 rec.close();

 // 9) replay guard cannot persist -> signed command gets the BLOCKING card with blocking copy, never auto-runs
 await a.close();
 fs.rmSync(cfg+'/glasswidgets/agent-seen.json',{force:true});fs.mkdirSync(cfg+'/glasswidgets/agent-seen.json'); // a directory where the store file should be
 ({a,A}=await launch());
 ts=Date.now();exp=EX();pushCmd({id:'s10',kind:'run_command',command:'touch '+m8,ts,exp,sig:sign('s10','run_command',ts,exp,'touch '+m8)});
 c=await card('touch '+m8);
 assert(/אישור הרצת פקודה/.test(c.title),'persist failure -> blocking card: '+c.title);
 assert(c.body.includes('בלי אישור'),'blocking copy, not auto-run copy: '+c.body);
 await sleep(3500);assert(!fs.existsSync(m8),'no auto-run when the replay guard cannot persist');

 // 11b) re-enroll AFTER restart-after-mint: a CLEAN relaunch on the same profile (scenario 9
 // sabotaged the seen store on purpose - remove the sabotage so signed envelopes verify again).
 await a.close();
 fs.rmSync(cfg+'/glasswidgets/agent-seen.json',{recursive:true,force:true});
 ({a,A}=await launch());
 const orchRe=createEnrollOrchestrator({sender:mkS(),approvePairing:async({fingerprint})=>fingerprint===devFpLocal});
 const rRe=await orchRe.run();
 assert(rRe.ok===true&&rRe.deviceId===devIdE,'post-restart re-enroll resolves the SAME device: '+JSON.stringify(rRe));
 assert(fdb.devices.size===1,'registry still holds exactly the one device');
 const devJ2=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/device/device.json','utf8'));
 assert(devJ2.pub===pubE,'identity unchanged across the restart');
 ctl.close();

 // 12) PAIRING GATE terminals: deny, restart-during-pending, expiry - each a DURABLE terminal
 // with NO key persisted; the bootstrap pending-read still lets the sender reconcile.
 await a.close();
 fs.rmSync(cfg+'/glasswidgets/device',{recursive:true,force:true}); // back to a NEVER-ENROLLED pc
 ({a,A}=await launch());
 const CH3='deny-'+Date.now().toString(36)+'-abcdefgh';
 ts=Date.now();exp=EX();pushCmd({id:'enr3',kind:'enroll_device',data:{challenge:CH3},ts,exp,sig:sign('enr3','enroll_device',ts,exp,JSON.stringify({challenge:CH3}))});
 await card('אישור צימוד טלפון');
 await clickBtn('אישור צימוד טלפון','דחה');
 const aDeny=await waitAck('enr3','failed');
 assert(/denied/.test(aDeny.note),'denied pairing is a durable failed terminal: '+aDeny.note);
 assert(!fs.existsSync(cfg+'/glasswidgets/device/device.json'),'deny persists NO key');
 for(let i=0;i<40&&fs.existsSync(cfg+'/glasswidgets/pairing-pending/enr3.json');i++)await sleep(100);
 assert(!fs.existsSync(cfg+'/glasswidgets/pairing-pending/enr3.json'),'deny clears THIS pending record after the durable terminal verified');
 const ledJ=()=>JSON.parse(fs.readFileSync(cfg+'/glasswidgets/agent-tunnel-ledger.json','utf8'));
 assert(ledJ()['enr3']&&ledJ()['enr3'].status==='failed'&&ledJ()['enr3'].terminal===true,'deny: the DURABLE LEDGER shows the failed terminal, not just the ack');
 // restart while parked: the boot recovery writes the durable terminal
 const CH4='rst-'+Date.now().toString(36)+'-abcdefgh';
 ts=Date.now();exp=EX();pushCmd({id:'enr4',kind:'enroll_device',data:{challenge:CH4},ts,exp,sig:sign('enr4','enroll_device',ts,exp,JSON.stringify({challenge:CH4}))});
 await card('אישור צימוד טלפון');
 assert(fs.existsSync(cfg+'/glasswidgets/pairing-pending/enr4.json'),'per-id pending record on disk before the restart');
 await a.close();
 ({a,A}=await launch());
 const aRst=await waitAck('enr4','failed');
 assert(/הופעלה מחדש/.test(aRst.note),'restart-during-parking is a durable failed terminal: '+aRst.note);
 assert(!fs.existsSync(cfg+'/glasswidgets/device/device.json'),'restart persists NO key');
 // the reload had converted the parked accepted record to FINAL unknown; the boot recovery must
 // RECONCILE it to a durable failed terminal - verified in the ledger itself, not only in the ack
 let led4=null;for(let i=0;i<40;i++){try{const r=ledJ()['enr4'];if(r&&r.status==='failed'){led4=r;break}}catch{}await sleep(200)}
 assert(led4&&led4.terminal===true,'post-restart ledger reconciled unknown->failed (durable): '+JSON.stringify(led4));
 for(let i=0;i<40&&fs.existsSync(cfg+'/glasswidgets/pairing-pending/enr4.json');i++)await sleep(100);
 assert(!fs.existsSync(cfg+'/glasswidgets/pairing-pending/enr4.json'),'recovery record cleared only AFTER the durable terminal verified');
 // the pending-read record SURVIVES the restart (set by the boot recovery), but /task stays
 // closed without a device key (reviewed endpoint boundary) - the sender reconciles a failed
 // pairing by retrying, which surfaces a NEW pairing card to the human
 const rT4=await read('-','/task','id=enr4');
 assert(rT4.status===503&&rT4.body&&rT4.body.error==='no_device_key','failed pairing on a never-enrolled pc: /task closed without a device key (503), pending record not cancelled');
 // expiry without a tap
 const CH5='exp-'+Date.now().toString(36)+'-abcdefgh';
 ts=Date.now();exp=EX();pushCmd({id:'enr5',kind:'enroll_device',data:{challenge:CH5},ts,exp,sig:sign('enr5','enroll_device',ts,exp,JSON.stringify({challenge:CH5}))});
 await card('אישור צימוד טלפון');
 const aExp=await waitAck('enr5','failed');
 assert(/expired/.test(aExp.note),'untouched pairing expires into a durable failed terminal: '+aExp.note);
 assert(!fs.existsSync(cfg+'/glasswidgets/device/device.json'),'expiry persists NO key');
 assert(ledJ()['enr5']&&ledJ()['enr5'].status==='failed'&&ledJ()['enr5'].terminal===true,'expiry: the DURABLE LEDGER shows the failed terminal');

 // cid-addressed card helpers (settled cards LINGER in the DOM - title search would hit stale ones)
 const cardCid=async cid=>{for(let i=0;i<40;i++){const c=await A.evaluate(x=>{const el=document.querySelector('#pillBody .card[data-cid="'+x+'"]');return el?el.querySelector('.cb').textContent:null},cid);if(c)return c;await sleep(200)}throw new Error('no card '+cid)};
 const clickCid=(cid,label)=>A.evaluate(([x,l])=>{const el=document.querySelector('#pillBody .card[data-cid="'+x+'"]');const b=[...el.querySelectorAll('button')].find(b=>b.textContent===l);if(b)b.click()},[cid,label]);
 // 12b) same-ID resend reconciles the DURABLE denied outcome over the EXISTING authenticated 409
 // channel: the sender retries its stored envelope, gets the cached failed outcome, NO new card.
 const sC=createSenderClient({deviceUrl:'http://127.0.0.1:47732',controlUrl:'http://127.0.0.1:9',replyKey:'rk-test',cmdKey:'cmd-key',signPrivate:SIGN_PRIV_B64,preEnroll:true,fetchImpl:fetch,outbox:memBox(),pollIntervalMs:50});
 const pC=await sC.prepare({kind:'enroll_device',data:{challenge:'rsd-'+Date.now().toString(36)+'-abcdefgh'}});
 const uC=await sC.send(pC);
 assert(uC.status==='accepted'&&uC.id,'fresh sender enroll accepted: '+JSON.stringify(uC));
 const uCid='local-approve-'+uC.id.replace(/[^\w-]/g,'').slice(0,60);
 await cardCid(uCid);
 await clickCid(uCid,'דחה');
 const aRsd=await waitAck(uC.id,'failed');
 assert(/denied/.test(aRsd.note),'sender-driven deny is a durable failed terminal: '+aRsd.note);
 assert(ledJ()[uC.id]&&ledJ()[uC.id].status==='failed','denied outcome durable in the ledger');
 const uC2=await sC.send({id:uC.id}); // the SAME stored envelope resent (sender restart shape)
 assert(uC2.status==='duplicate'&&uC2.outcome&&uC2.outcome.outcome&&uC2.outcome.outcome.status==='failed','same-ID resend reconciles the cached DENIED outcome via 409: '+JSON.stringify(uC2));
 const audRs=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert((audRs.match(new RegExp('"stage":"pairing_requested","id":"'+uC.id.slice(0,40).replace(/[^\w-]/g,'')+'"','g'))||[]).length===1,'the resend published NO second card (one pairing_requested for the id)');

 // 12c) A/B interleave: two parked pairings; approving A enrolls A; approving the STALE B must
 // NEVER claim success on a different key - superseded is a durable failed terminal.
 const CHa='ia-'+Date.now().toString(36)+'-abcdefgh',CHb='ib-'+Date.now().toString(36)+'-abcdefgh';
 ts=Date.now();exp=EX();pushCmd({id:'enrA',kind:'enroll_device',data:{challenge:CHa},ts,exp,sig:sign('enrA','enroll_device',ts,exp,JSON.stringify({challenge:CHa}))});
 ts=Date.now();exp=EX();pushCmd({id:'enrB',kind:'enroll_device',data:{challenge:CHb},ts,exp,sig:sign('enrB','enroll_device',ts,exp,JSON.stringify({challenge:CHb}))});
 const bodyA=await cardCid('local-approve-enrA'),bodyB=await cardCid('local-approve-enrB');
 const fpA=(bodyA.match(/[0-9a-f]{4}(-[0-9a-f]{4}){3}/)||[])[0],fpB=(bodyB.match(/[0-9a-f]{4}(-[0-9a-f]{4}){3}/)||[])[0];
 assert(fpA&&fpB&&fpA!==fpB,'two parked pairings show DIFFERENT candidate fingerprints: '+fpA+' vs '+fpB);
 await clickCid('local-approve-enrA','אשר צימוד');
 const aA=await waitAck('enrA','done');
 assert(aA.result&&aA.result.pairing&&aA.result.pairing.fingerprint===fpA&&aA.result.pairing.cardId==='local-approve-enrA','A enrolled with ITS shown fingerprint + card: '+JSON.stringify(aA.result.pairing));
 await clickCid('local-approve-enrB','אשר צימוד');
 const aB=await waitAck('enrB','failed');
 assert(/superseded/.test(aB.note),'stale B NEVER succeeds on a different key: '+aB.note);
 const{fingerprint:fpOf}=require(REPO+'/src/lib/fingerprint');
 const devJ3=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/device/device.json','utf8'));
 assert(fpOf(devJ3.pub)===fpA,'the enrolled identity is A (the approved fingerprint), never B');
 assert(ledJ()['enrB']&&ledJ()['enrB'].status==='failed'&&ledJ()['enrB'].terminal===true,'B superseded is a DURABLE failed terminal');
 for(let i=0;i<40&&(fs.existsSync(cfg+'/glasswidgets/pairing-pending/enrA.json')||fs.existsSync(cfg+'/glasswidgets/pairing-pending/enrB.json'));i++)await sleep(100);
 assert(!fs.existsSync(cfg+'/glasswidgets/pairing-pending/enrA.json')&&!fs.existsSync(cfg+'/glasswidgets/pairing-pending/enrB.json'),'both recovery records cleared after their terminals verified');
 const aud2=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(aud2.includes('"stage":"pairing_requested"')&&aud2.includes('"stage":"pairing_expired"')&&aud2.includes('"stage":"pairing_restart_cancel"')&&aud2.includes('"stage":"denied"')&&aud2.includes('"stage":"pairing_superseded"'),'pairing audit trail complete: requested/approved-or-denied/expired/restart-cancel/superseded');
 console.log('AGENT-SIG TESTS PASSED');await a.close();srv.close();process.exit(0);
})().catch(e=>{console.error('FAIL',e);try{console.error('AUDIT-TAIL:\n'+fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8').split('\n').slice(-12).join('\n'))}catch{}try{console.error('ACKS:',JSON.stringify(ACK.slice(-8)))}catch{}process.exit(1)});
