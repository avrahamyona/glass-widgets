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
  GLASSWIDGETS_APPROVAL_TTL_MS:'4000',GLASSWIDGETS_AUTO_RUN_MS:'2500',GLASSWIDGETS_AGENT_SIGN_PUB:PUB_B64,GLASSWIDGETS_WEB_TASK_ALLOW_LOCAL:'1'};
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
 await sleep(1500);assert(!ACK.some(x=>x.id==='s1'),'replay: audit-only, no ack (a dup ack would clobber the real result)');
 const seen=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/agent-seen.json','utf8'));
 assert(seen.s1&&seen.s1.decision==='executed'&&seen.s1.exp===exp,'seen store persisted decision+exp: '+JSON.stringify(seen.s1));
 // 1c) replay after RESTART: relaunch with the same profile, same signed message -> still duplicate
 await a.close();
 ({a,A}=await launch());
 ACK=ACK.filter(x=>x.id!=='s1');
 pushCmd({id:'s1',kind:'run_command',command:'touch '+m1,ts,exp,sig:sign('s1','run_command',ts,exp,'touch '+m1)});
 await sleep(1500);assert(!ACK.some(x=>x.id==='s1'),'replay after restart: no ack, original result stands');
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
 c=await card('touch '+m4);
 assert(/אישור הרצת פקודה/.test(c.title),'expired exp -> blocking card: '+c.title);
 await sleep(1500);assert(!fs.existsSync(m4),'expired sig never auto-executes');
 await clickBtn('touch '+m4,'דחה');
 // 6) ts too far in the FUTURE: blocking card
 ts=Date.now()+120000;exp=ts+60000;pushCmd({id:'s6',kind:'run_command',command:'touch '+m5,ts,exp,sig:sign('s6','run_command',ts,exp,'touch '+m5)});
 c=await card('touch '+m5);
 assert(/אישור הרצת פקודה/.test(c.title),'future ts -> blocking card: '+c.title);
 await sleep(1500);assert(!fs.existsSync(m5),'future-ts never auto-executes');
 await clickBtn('touch '+m5,'דחה');
 // 7) exp<=ts: blocking card
 ts=Date.now();exp=ts-1000;pushCmd({id:'s7',kind:'run_command',command:'touch '+m5,ts,exp,sig:sign('s7','run_command',ts,exp,'touch '+m5)});
 c=await card('touch '+m5);
 assert(/אישור הרצת פקודה/.test(c.title),'exp<=ts -> blocking card: '+c.title);
 await clickBtn('touch '+m5,'דחה');
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

 // 9) replay guard cannot persist -> signed command gets the BLOCKING card with blocking copy, never auto-runs
 await a.close();
 fs.rmSync(cfg+'/glasswidgets/agent-seen.json',{force:true});fs.mkdirSync(cfg+'/glasswidgets/agent-seen.json'); // a directory where the store file should be
 ({a,A}=await launch());
 ts=Date.now();exp=EX();pushCmd({id:'s10',kind:'run_command',command:'touch '+m8,ts,exp,sig:sign('s10','run_command',ts,exp,'touch '+m8)});
 c=await card('touch '+m8);
 assert(/אישור הרצת פקודה/.test(c.title),'persist failure -> blocking card: '+c.title);
 assert(c.body.includes('בלי אישור'),'blocking copy, not auto-run copy: '+c.body);
 await sleep(3500);assert(!fs.existsSync(m8),'no auto-run when the replay guard cannot persist');
 console.log('AGENT-SIG TESTS PASSED');await a.close();srv.close();process.exit(0);
})().catch(e=>{console.error('FAIL',e);try{console.error('AUDIT-TAIL:\n'+fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8').split('\n').slice(-12).join('\n'))}catch{}try{console.error('ACKS:',JSON.stringify(ACK.slice(-8)))}catch{}process.exit(1)});
