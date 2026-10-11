const REPO=process.env.GW_REPO||'/home/sandbox/glass-widgets';
const {_electron:e}=require(REPO+'/node_modules/playwright');const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),crypto=require('crypto');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const {publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const PUB_B64=PUB.export({format:'der',type:'spki'}).toString('base64');
const sign=(id,kind,ts,exp,payload)=>crypto.sign(null,Buffer.from([id,kind,String(ts),String(exp),payload].join('\n'),'utf8'),PRIV).toString('hex');
let ACK=[],CMDQS=[],UPLOADS=[];
const srv=http.createServer((q,r)=>{const u=new URL(q.url,'http://x');
 if(u.pathname==='/chat/stream'){r.writeHead(200,{'content-type':'text/event-stream'});r.write(': ready\n\n');return}
 if(u.pathname==='/chat'&&q.method==='GET'){r.writeHead(200,{'content-type':'application/json'});r.end('{"ok":true,"read_upto":0,"messages":[]}');return}
 if(u.pathname==='/chat'&&q.method==='POST'){let b='';q.on('data',d=>b+=d);q.on('end',()=>{r.writeHead(200,{'content-type':'application/json'});r.end('{"ok":true,"id":"x1"}')});return}
 if(u.pathname==='/chat/action'&&q.method==='POST'){r.writeHead(200,{'content-type':'application/json'});r.end('{"ok":true}');return}
 if(u.pathname==='/cmd/stream'){CMDQS.push(u.search);r.writeHead(200,{'content-type':'text/event-stream'});r.write(': ready\n\n');global.cmdRes=r;return}
 if(u.pathname==='/cmd/ack'){let b='';q.on('data',d=>b+=d);q.on('end',()=>{ACK.push(JSON.parse(b||'{}'));r.end('{"updated":1}')});return}
 if(u.pathname==='/cmd/ack-blind'){let b='';q.on('data',d=>b+=d);q.on('end',()=>{r.writeHead(200,{'content-type':'application/json'});r.end('{}')});return} // 2xx without updated:1 - landing unconfirmed
 if(u.pathname==='/file/upload'){let n=0;q.on('data',d=>n+=d.length);q.on('end',()=>{UPLOADS.push({name:u.searchParams.get('name'),bytes:n,key:q.headers['x-gw-key']});r.writeHead(200,{'content-type':'application/json'});r.end('{"file_id":"f-'+UPLOADS.length+'"}')});return}
 r.statusCode=404;r.end()});
const pushCmd=m=>{if(global.cmdRes)global.cmdRes.write('data: '+JSON.stringify(m)+'\n\n')};
const EX=()=>Date.now()+300000;
const waitAck=async(id,status)=>{for(let i=0;i<50;i++){const a=ACK.find(x=>x.id===id&&x.status===status);if(a)return a;await sleep(200)}const dump=fs.existsSync(cfg+'/glasswidgets/agent-audit.log')?fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8').split('\n').filter(l=>l.includes(id)).join('\n'):'no-log';throw new Error('no ack '+id+' '+status+' in '+JSON.stringify(ACK.slice(-6))+' AUDIT: '+dump)};
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
 cfg=fs.mkdtempSync('/tmp/gw-ui-');fs.mkdirSync(cfg+'/glasswidgets',{recursive:true});
 fs.writeFileSync(cfg+'/glasswidgets/instances.json',JSON.stringify([{id:'chat',type:'chat'}]));
 fs.writeFileSync(cfg+'/glasswidgets/settings.json',JSON.stringify({instanceConfigs:{chat:{size:'island'}}}));
 env={...process.env,XDG_CONFIG_HOME:cfg,GLASSWIDGETS_NO_PICKER:'1',PYTHONPATH:'/tmp/pystub',GLASSWIDGETS_CLOUD_PYTHON:'/usr/bin/python3',
  GLASSWIDGETS_CHAT_URL:'http://127.0.0.1:'+port+'/chat',GLASSWIDGETS_CHAT_STREAM_URL:'http://127.0.0.1:'+port+'/chat/stream',
  GLASSWIDGETS_CHAT_KEY:'chat-key',GLASSWIDGETS_AGENT_CMD_KEY:'cmd-key',GLASSWIDGETS_AGENT_CMD_URL:'http://127.0.0.1:'+port+'/cmd/stream',GLASSWIDGETS_AGENT_ACK_URL:'http://127.0.0.1:'+port+'/cmd/ack',
  GLASSWIDGETS_APPROVAL_TTL_MS:'4000',GLASSWIDGETS_AUTO_RUN_MS:'2500',GLASSWIDGETS_AGENT_SIGN_PUB:PUB_B64,GLASSWIDGETS_UI_DRYRUN:'1',GLASSWIDGETS_LOCAL_SERVER_PORT:'47731',GLASSWIDGETS_TUNNEL_ENABLED:'0'};
 global.cmdRes=null;
 let {a,A}=await launch();
 assert(CMDQS[0].includes('ui')&&CMDQS[0].includes('shot')&&CMDQS[0].includes('island'),'caps advertise ui+shot+island: '+CMDQS[0]);
 const card=async find=>{for(let i=0;i<40;i++){const c=await A.evaluate(f=>{const els=[...document.querySelectorAll('#pillBody .card')];const el=els.find(e=>e.textContent.includes(f));return el?{cid:el.dataset.cid,title:el.querySelector('.ct').textContent,body:el.querySelector('.cb')?el.querySelector('.cb').textContent:'',btns:[...el.querySelectorAll('button')].map(b=>b.textContent)}:null},find);if(c)return c;await sleep(200)}throw new Error('no card matching '+find)};
 const clickBtn=(find,label)=>A.evaluate(([f,l])=>{const el=[...document.querySelectorAll('#pillBody .card')].find(e=>e.textContent.includes(f));const b=[...el.querySelectorAll('button')].find(b=>b.textContent===l);if(b)b.click()},[find,label]);

 // 1) unsigned ui_automation: blocking card showing the COMPLETE plan, approve -> executes (dry-run)
 pushCmd({id:'u1',kind:'ui_automation',label:'עדכון Efi Music',steps:[{do:'click',x:100,y:200},{do:'wait',ms:500},{do:'dblclick',x:300,y:400}]});
 let c=await card('עדכון Efi Music');
 assert(/אישור לחיצות על המסך/.test(c.title),'blocking card title: '+c.title);
 assert.deepEqual(c.btns,['אשר','דחה'],'blocking buttons');
 assert(c.body.includes('לחיצה ב-(x:100, y:200)')&&c.body.includes('המתנה 500ms')&&c.body.includes('לחיצה כפולה ב-(x:300, y:400)'),'complete plan on card: '+c.body);
 await clickBtn('עדכון Efi Music','אשר');
 let a1=await waitAck('u1','done');
 assert(a1.result&&a1.result.steps&&a1.result.steps.length===3&&a1.result.steps.every(s=>s.ok&&(s.do==='wait'||s.dry)),'3 dry steps ok: '+JSON.stringify(a1.result));

 // 2) deny path: no execution
 pushCmd({id:'u2',kind:'ui_automation',steps:[{do:'click',x:50,y:50}]});
 c=await card('לחיצה ב-(x:50, y:50)');
 await clickBtn('לחיצה ב-(x:50, y:50)','דחה');
 assert(/denied/.test((await waitAck('u2','failed')).note||''),'denied ack');

 // 3) signed ui_automation: cancelable auto-run card, executes without a tap
 const steps3=[{do:'move',x:500,y:500},{do:'click',x:600,y:600}];
 let ts=Date.now(),exp=EX();
 pushCmd({id:'u3',kind:'ui_automation',steps:steps3,ts,exp,sig:sign('u3','ui_automation',ts,exp,JSON.stringify(steps3))});
 c=await card('הזזת עכבר ב-(x:500, y:500)');
 assert(/⚡ מבצע לחיצות שאישרת/.test(c.title),'auto card title: '+c.title);
 assert.deepEqual(c.btns,['בטל'],'only cancel');
 const a3=await waitAck('u3','done');
 assert(a3.result.steps.length===2&&a3.result.steps[0].do==='move','auto-ran signed plan');

 // 3b) replay: same signed id again -> duplicate is audit-only, NO ack (a dup ack would clobber the real result)
 ACK=ACK.filter(x=>x.id!=='u3');
 pushCmd({id:'u3',kind:'ui_automation',steps:steps3,ts,exp,sig:sign('u3','ui_automation',ts,exp,JSON.stringify(steps3))});
 await sleep(1500);
 assert(!ACK.some(x=>x.id==='u3'),'replay produces no ack: '+JSON.stringify(ACK.filter(x=>x.id==='u3')));

 // 4) bad sig -> blocking card, no auto-run
 ts=Date.now();exp=EX();
 pushCmd({id:'u4',kind:'ui_automation',steps:[{do:'click',x:111,y:222}],ts,exp,sig:'ab'.repeat(64)});
 c=await card('לחיצה ב-(x:111, y:222)');
 assert(/אישור לחיצות על המסך/.test(c.title),'bad sig -> blocking card');
 await clickBtn('לחיצה ב-(x:111, y:222)','דחה');
 await waitAck('u4','failed');

 // 5) invalid plans: refused without a card
 pushCmd({id:'u5',kind:'ui_automation',steps:[{do:'type',x:1,y:1,text:'hi'}]});
 assert(/bad ui plan/.test((await waitAck('u5','failed')).note||''),'unknown action refused');
 pushCmd({id:'u6',kind:'ui_automation',steps:[{do:'click',x:-99999,y:1}]});
 assert(/bad ui plan/.test((await waitAck('u6','failed')).note||''),'off-screen coords refused');
 pushCmd({id:'u7',kind:'ui_automation',steps:Array.from({length:21},()=>({do:'wait',ms:100}))});
 assert(/bad ui plan/.test((await waitAck('u7','failed')).note||''),'>20 steps refused');
 pushCmd({id:'u8',kind:'ui_automation',steps:[{do:'wait',ms:99999}]});
 assert(/bad ui plan/.test((await waitAck('u8','failed')).note||''),'overlong wait refused');
 pushCmd({id:'u9',kind:'ui_automation',steps:[]});
 assert(/bad ui plan/.test((await waitAck('u9','failed')).note||''),'empty plan refused');

 // 6) unsigned duplicate id with a parked card: refused, original intact
 pushCmd({id:'u10',kind:'ui_automation',steps:[{do:'click',x:10,y:10}]});
 c=await card('לחיצה ב-(x:10, y:10)');
 ACK=ACK.filter(x=>x.id!=='u10');
 pushCmd({id:'u10',kind:'ui_automation',steps:[{do:'click',x:20,y:20}]});
 await sleep(1200);
 assert(!ACK.some(x=>x.id==='u10'),'dup of parked card produces no ack: '+JSON.stringify(ACK.filter(x=>x.id==='u10')));
 await clickBtn('לחיצה ב-(x:10, y:10)','אשר');
 await waitAck('u10','done');
 await sleep(600);
 assert(ACK.filter(x=>x.id==='u10').length===1,'exactly one ack for u10 (the real result): '+JSON.stringify(ACK.filter(x=>x.id==='u10')));

 // 7) screenshot: captures, uploads PNG with cmd key, returns geometry for coord mapping
 pushCmd({id:'sh1',kind:'screenshot'});
 const ash=await waitAck('sh1','done');
 assert(ash.result&&ash.result.file_id==='f-1'&&ash.result.bytes>1000,'screenshot uploaded: '+JSON.stringify(ash.result));
 assert(ash.result.img_width>0&&ash.result.logical_width>0&&ash.result.scale>=1,'geometry returned: '+JSON.stringify(ash.result));
 assert(Number.isFinite(ash.result.origin_x)&&Number.isFinite(ash.result.origin_y)&&ash.result.coord&&ash.result.coord.startsWith('physical'),'origin + physical coord contract: '+JSON.stringify(ash.result));
 assert(ash.result.one_to_one===true&&ash.result.px_per_img_x===1&&ash.result.px_per_img_y===1,'measured 1:1 mapping: '+JSON.stringify(ash.result));
 assert(UPLOADS[0]&&UPLOADS[0].key==='cmd-key'&&UPLOADS[0].name.startsWith('screenshot-sh1'),'upload keyed+named: '+JSON.stringify(UPLOADS[0]));

 // 10) island_control: unsigned -> blocking card, approve -> pill opens in the island window
 const pillOpen=()=>A.evaluate(()=>document.getElementById('pill').classList.contains('open'));
 // earlier approval cards auto-open the island - close it first through island_control itself
 pushCmd({id:'i0',kind:'island_control',action:'close'});
 c=await card('סגירת האי');
 await clickBtn('סגירת האי','אשר');
 await waitAck('i0','done');
 for(let i=0;i<20&&(await pillOpen());i++)await sleep(150);
 assert(!(await pillOpen()),'island_control close closed the pill (from card-opened state)');
 pushCmd({id:'i1',kind:'island_control',action:'open'});
 c=await card('פתיחת האי');
 assert(/אישור פעולה על האי/.test(c.title),'island blocking card title: '+c.title);
 assert.deepEqual(c.btns,['אשר','דחה'],'island blocking buttons');
 await clickBtn('פתיחת האי','אשר');
 await waitAck('i1','done');
 for(let i=0;i<20&&!(await pillOpen());i++)await sleep(150);
 assert(await pillOpen(),'island_control open opened the pill');
 // signed close -> cancelable auto-run card, pill closes without a tap
 ts=Date.now();exp=EX();
 pushCmd({id:'i2',kind:'island_control',action:'close',ts,exp,sig:sign('i2','island_control',ts,exp,'close')});
 c=await card('פעולת אי שאישרת'); // match the auto card uniquely - i0's stale blocking card shares the action text
 assert(/⚡ מבצע פעולת אי שאישרת/.test(c.title),'island auto card title: '+c.title);
 assert.deepEqual(c.btns,['בטל'],'island auto card: only cancel');
 await waitAck('i2','done');
 for(let i=0;i<20&&(await pillOpen());i++)await sleep(150);
 assert(!(await pillOpen()),'island_control close closed the pill');
 // unknown action refused without a card - including inherited-object keys (constructor/toString/__proto__)
 pushCmd({id:'i3',kind:'island_control',action:'spin'});
 assert(/unknown island action/.test((await waitAck('i3','failed')).note||''),'bad island action refused');
 pushCmd({id:'i5',kind:'island_control',action:'toString'});
 assert(/unknown island action/.test((await waitAck('i5','failed')).note||''),'inherited key refused');
 // 11) dup-race regression: same signed id delivered twice (worker retry) -> exactly ONE ack, the real result
 ts=Date.now();exp=EX();const sig11=sign('i4','island_control',ts,exp,'open');
 pushCmd({id:'i4',kind:'island_control',action:'open',ts,exp,sig:sig11});
 pushCmd({id:'i4',kind:'island_control',action:'open',ts,exp,sig:sig11});
 await waitAck('i4','done');
 await sleep(1500);
 assert(ACK.filter(x=>x.id==='i4').length===1,'dup delivery: exactly one ack: '+JSON.stringify(ACK.filter(x=>x.id==='i4')));
 assert(/renderer confirmed open/.test(ACK.find(x=>x.id==='i4').note||''),'done ack means renderer-confirmed state: '+ACK.find(x=>x.id==='i4').note);
 assert(await pillOpen(),'dup delivery: the real execution still ran');
 const log11=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(log11.includes('"stage":"duplicate"'),'audit records the duplicate delivery');

 // 11b) close ack wording: 'closed', not the raw action string
 assert(/renderer confirmed closed/.test(ACK.find(x=>x.id==='i2').note||''),'closed wording: '+ACK.find(x=>x.id==='i2').note);

 // 11c) lifecycle settling on the MOUNTED pill: settle events (not age) drive the refresh
 let ptxt=await A.evaluate(()=>{const l=document.getElementById('pillLog');return l?l.textContent:''});
 assert(!ptxt.includes('סגירת האי')&&!ptxt.includes('עדכון Efi Music')&&!ptxt.includes('פעולת אי שאישרת'),'settled/acted cards out of the mounted pill: '+ptxt.slice(0,120));
 pushCmd({id:'iA',kind:'island_control',action:'open'});
 c=await card('פתיחת האי'); // unsigned -> blocking pending card
 ptxt=await A.evaluate(()=>document.getElementById('pillLog').textContent);
 assert(ptxt.includes('פתיחת האי'),'fresh pending card visible in the pill');
 await sleep(5200); // APPROVAL_TTL_MS=4000: the agent's expiry settle must refresh the mounted panel by itself
 ptxt=await A.evaluate(()=>document.getElementById('pillLog').textContent);
 assert(!ptxt.includes('פתיחת האי'),'expiry settle refreshed the mounted pill without any further event: '+ptxt.slice(0,120));
 const mainLog=await A.evaluate(()=>{const l=document.getElementById('log');return l?l.textContent:''});
 assert(mainLog.includes('עדכון Efi Music')&&mainLog.includes('פתיחת האי'),'main chat log keeps full card history');
 const greyed=await A.evaluate(()=>{const el=[...document.querySelectorAll('#log .card')].find(e=>e.dataset.cid==='local-approve-iA');return el?el.className:'missing'});
 assert(/acted/.test(greyed),'expired card shows dead/greyed in history: '+greyed);

 // 11d) hover audit: a real renderer mouseenter is recorded with its fire-time mode
 ts=Date.now();exp=EX();
 pushCmd({id:'i9',kind:'island_control',action:'close',ts,exp,sig:sign('i9','island_control',ts,exp,'close')});
 await waitAck('i9','done');
 for(let i=0;i<20&&(await pillOpen());i++)await sleep(150);
 await A.hover('#pillHead');await sleep(400);
 const logH=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"island_hover","mode":"mini","instance":"chat"/.test(logH),'closed-mode hover recorded with island provenance: '+logH.split('\n').filter(l=>l.includes('island_hover')).join('|'));

 // 11e) raw delivery probe: every renderer-seen move in mini mode is audited (throttled), with over-pill provenance
 const countMoves=()=>((fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8').match(/"kind":"island_move"/g))||[]).length;
 const before=countMoves();
 await A.evaluate(()=>{const p=document.getElementById('pill');const r=p.getBoundingClientRect();
  for(let i=0;i<3;i++)p.dispatchEvent(new MouseEvent('mousemove',{bubbles:true,clientX:r.x+5,clientY:r.y+5}));});
 await sleep(300);
 assert(countMoves()-before===1,'3 rapid moves throttle to one island_move line, got '+(countMoves()-before));
 let logM=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"island_move"[^\n]*"mode":"mini"[^\n]*"over":true/.test(logM),'probe carries mode+over-pill provenance');
 await sleep(350);
 await A.evaluate(()=>{document.dispatchEvent(new MouseEvent('mousemove',{bubbles:true,clientX:2,clientY:2}))});
 await sleep(300);
 assert(countMoves()-before===2,'post-throttle move logged as second line');
 logM=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"island_move"[^\n]*"over":false/.test(logM),'off-pill move logged with over:false');
 // move lines carry per-window provenance; invalid payloads are rejected, never coerced into trusted audit
 assert(/"kind":"island_move"[^\n]*"src":"primary","wid":\d+/.test(logM),'move line carries source role + webContents id');
 const beforeBad=countMoves();
 await A.evaluate(()=>{window.api.pillMove({x:NaN,y:1,mode:'mini',over:true});window.api.pillMove({x:1,y:1,mode:'open',over:true});window.api.pillMove({x:1,y:1,mode:'mini',over:'yes'})});
 await sleep(300);
 assert(countMoves()===beforeBad,'invalid move payloads rejected (non-finite coord, wrong mode, non-boolean over)');
 // passthrough TRANSITIONS are audited with validated provenance (not per-invocation spam)
 assert(/"kind":"island_passthrough","on":false[^\n]*"source":"island"/.test(logM)&&/"kind":"island_passthrough","on":true[^\n]*"source":"island"/.test(logM),'passthrough transitions audited with island provenance');
 const ptLines=(logM.match(/"kind":"island_passthrough"/g)||[]).length;
 await A.evaluate(()=>{window.api.chatPassthrough(true);window.api.chatPassthrough(true);window.api.chatPassthrough(true)});
 await sleep(300);
 logM=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert((logM.match(/"kind":"island_passthrough"/g)||[]).length===ptLines,'repeat same-state passthrough calls add NO audit lines (transitions only)');

 // 12) absent DOM: pill element removed -> close can never falsely confirm, bounded failure
 await A.evaluate(()=>{const p=document.getElementById('pill');p.remove()});
 ts=Date.now();exp=EX();
 pushCmd({id:'i6',kind:'island_control',action:'close',ts,exp,sig:sign('i6','island_control',ts,exp,'close')});
 const a6=await waitAck('i6','failed');
 assert(/did not reach close/.test(a6.note||''),'absent DOM: close fails instead of confirming: '+a6.note);

 // 13) hung renderer: blocked JS loop -> probes race out, the bridge still answers within its bound
 A.evaluate(()=>{while(true){}}).catch(()=>{}); // never resolves - do not await
 ts=Date.now();exp=EX();
 pushCmd({id:'i7',kind:'island_control',action:'open',ts,exp,sig:sign('i7','island_control',ts,exp,'open')});
 const t13=Date.now();
 const a7=await waitAck('i7','failed');
 assert(Date.now()-t13<15000,'hung renderer: bridge answered within bound: '+(Date.now()-t13)+'ms');
 assert(/did not reach open/.test(a7.note||''),'hung renderer: failed, not stranded: '+a7.note);
 await a.close();global.cmdRes=null;({a,A}=await launch());

 // 14) destroyed primary: window gone -> failed ack, never dispatch-only 'done'
 await A.close();await sleep(500);
 ts=Date.now();exp=EX();
 pushCmd({id:'i8',kind:'island_control',action:'open',ts,exp,sig:sign('i8','island_control',ts,exp,'open')});
 const a8=await waitAck('i8','failed');
 assert(/island primary window unavailable|no island/.test(a8.note||''),'destroyed primary fails: '+a8.note);
 await a.close();global.cmdRes=null;({a,A}=await launch()); // fresh windows for the audit/deadline scenarios

 // 8) audit trail
 const log=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 for(const k of ['"ui_automation"','"screenshot"','"preapproved"','"step"','"island_control"'])assert(log.includes(k),'audit has '+k);

 // 9) hard task deadline: waits beyond the budget never run
 await a.close();
 env={...env,GLASSWIDGETS_UI_TASK_MS:'2000'};
 global.cmdRes=null;
 ({a,A}=await launch());
 const steps9=[{do:'wait',ms:1500},{do:'wait',ms:1500},{do:'click',x:100,y:200}];
 ts=Date.now();exp=EX();
 pushCmd({id:'u11',kind:'ui_automation',steps:steps9,ts,exp,sig:sign('u11','ui_automation',ts,exp,JSON.stringify(steps9))});
 const a11=await waitAck('u11','failed');
 assert(/deadline/.test(a11.note||''),'deadline stop: '+a11.note);
 assert(a11.result&&a11.result.deadline===true&&a11.result.steps.filter(x=>x.ok).length<=2,'stopped before the expired step: '+JSON.stringify(a11.result));

 // 10) ack observability: a rejected ack and a dead ack endpoint are both audited, never silent
 await a.close();global.cmdRes=null;
 env={...env,GLASSWIDGETS_AGENT_ACK_URL:'http://127.0.0.1:'+port+'/nope'}; // server 404s unknown paths
 ({a,A}=await launch());
 let steps10=[{do:'wait',ms:10}];
 ts=Date.now();exp=EX();
 pushCmd({id:'ak1',kind:'ui_automation',steps:steps10,ts,exp,sig:sign('ak1','ui_automation',ts,exp,JSON.stringify(steps10))});
 await sleep(4500); // auto-run 2.5s + dry-run exec + rejected ack
 let logA=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"ack","stage":"http_error","id":"ak1","status":"\w+","http":404/.test(logA),'rejected ack audited with http status: '+logA.split('\n').filter(l=>l.includes('"ack"')).join('|'));
 await a.close();global.cmdRes=null;
 env={...env,GLASSWIDGETS_AGENT_ACK_URL:'http://127.0.0.1:9/none'}; // dead endpoint
 ({a,A}=await launch());
 steps10=[{do:'wait',ms:10}];
 ts=Date.now();exp=EX();
 pushCmd({id:'ak2',kind:'ui_automation',steps:steps10,ts,exp,sig:sign('ak2','ui_automation',ts,exp,JSON.stringify(steps10))});
 await sleep(4500);
 logA=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"ack","stage":"send_failed","id":"ak2"/.test(logA),'dead ack endpoint audited with reason: '+logA.split('\n').filter(l=>l.includes('"ack"')).join('|'));
 await a.close();global.cmdRes=null;
 env={...env,GLASSWIDGETS_AGENT_ACK_URL:'http://127.0.0.1:'+port+'/cmd/ack-blind'}; // 2xx, no updated field
 ({a,A}=await launch());
 steps10=[{do:'wait',ms:10}];
 ts=Date.now();exp=EX();
 pushCmd({id:'ak3',kind:'ui_automation',steps:steps10,ts,exp,sig:sign('ak3','ui_automation',ts,exp,JSON.stringify(steps10))});
 await sleep(4500);
 logA=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"ack","stage":"ack_unconfirmed","id":"ak3"/.test(logA),'2xx without updated:1 audited as unconfirmed, not as landed');

 // 11) pathological escaping: 4000 double-quotes on stdout must still land within the serialized bounds
 await a.close();global.cmdRes=null;
 env={...env,GLASSWIDGETS_AGENT_ACK_URL:'http://127.0.0.1:'+port+'/cmd/ack'};
 ({a,A}=await launch());
 const flood=`printf '%.0s"' $(seq 1 4000)`;
 ts=Date.now();exp=EX();
 pushCmd({id:'ak4',kind:'run_command',command:flood,ts,exp,sig:sign('ak4','run_command',ts,exp,flood)});
 const aFlood=await waitAck('ak4','done');
 const wire=JSON.stringify(aFlood.result||{});
 assert(wire.length<=3500,'serialized result within worker cap, got '+wire.length);
 assert(aFlood.result.truncated===true&&aFlood.result.stdout_full===4000,'explicit truncation metadata: '+JSON.stringify({truncated:aFlood.result.truncated,full:aFlood.result.stdout_full}));
 logA=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(!logA.includes('"kind":"ack","stage":"http_error","id":"ak4"')&&!logA.includes('"ack_unconfirmed","id":"ak4"'),'truncated result landed confirmed (no ack anomaly for ak4)');

 // 15) tunnel intake: unsigned envelope -> 403 audited, signed envelope -> 202 -> executes+acks, replay -> 409
 await a.close();global.cmdRes=null;
 ({a,A}=await launch());
 const TUN='http://127.0.0.1:47731/cmd';
 const tunPost=async body=>{const r=await fetch(TUN,{method:'POST',headers:{'content-type':'application/json','X-GW-Key':'cmd-key'},body:JSON.stringify(body)});let j=null;try{j=await r.json()}catch{};return{status:r.status,body:j}};
 for(let i=0;i<50;i++){try{const h=await fetch('http://127.0.0.1:47731/health',{headers:{'X-GW-Key':'cmd-key'}});if(h.ok)break}catch{};await sleep(200)}
 const noAuth=await fetch(TUN,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
 assert(noAuth.status===403,'tunnel /cmd without the key -> 403');
 const un=await tunPost({id:'t1',kind:'find_files',data:{query:'__no_such__'}});
 assert(un.status===403&&un.body.reason==='unsigned','unsigned envelope -> 403 unsigned: '+JSON.stringify(un));
 logA=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"kind":"server","stage":"unsigned_cmd","id":"t1"/.test(logA),'unsigned tunnel attempt audited');
 const data1={query:'__no_such_file_xyz__',limit:3};
 ts=Date.now();exp=EX();
 const sig1=sign('t2','find_files',ts,exp,JSON.stringify(data1));
 const ok1=await tunPost({id:'t2',kind:'find_files',ts,exp,sig:sig1,data:data1});
 assert(ok1.status===202,'signed envelope -> 202: '+JSON.stringify(ok1));
 const aT=await waitAck('t2','done');
 assert(aT.result&&Array.isArray(aT.result.matches),'tunnel find_files executed and acked: '+JSON.stringify(aT.result).slice(0,120));
 const dup=await tunPost({id:'t2',kind:'find_files',ts,exp,sig:sig1,data:data1});
 assert(dup.status===409,'signed replay -> 409 duplicate');
 ts=Date.now();exp=EX()-600000; // stale window: exp already in the past
 const stale=await tunPost({id:'t3',kind:'find_files',ts,exp,sig:sign('t3','find_files',ts,exp,JSON.stringify({query:'x'})),data:{query:'x'}});
 assert(stale.status===403,'expired envelope -> 403');
 const badData=await tunPost({id:'t4',kind:'find_files',ts:Date.now(),exp:EX(),sig:sign('t4','find_files',Date.now(),EX(),'{"query":"other"}'),data:{query:'changed'}});
 assert(badData.status===403,'signature over different payload -> 403 (envelope binds the data)');

 // 15b) reserved fields inside signed data are rejected - signed data can never smuggle identity
 ts=Date.now();exp=EX();
 const dataR={query:'x',id:'t2',sig:'aa'};
 const rsv=await tunPost({id:'t5',kind:'find_files',ts,exp,sig:sign('t5','find_files',ts,exp,JSON.stringify(dataR)),data:dataR});
 assert(rsv.status===400&&rsv.body.reason==='reserved_field','reserved key in data -> 400: '+JSON.stringify(rsv));

 // 15c) parked kind via tunnel: 202, ordinary blocking card (unsigned semantics downstream),
 // the intake replay record does NOT eat the first command, and a signed replay -> 409
 ts=Date.now();exp=EX();
 const dataC={command:'echo tunnel-card-test'};
 const sigC=sign('t6','run_command',ts,exp,JSON.stringify(dataC));
 const okC=await tunPost({id:'t6',kind:'run_command',ts,exp,sig:sigC,data:dataC});
 assert(okC.status===202,'signed run_command via tunnel -> 202');
 const cardC=await card('echo tunnel-card-test');
 assert(cardC.btns.some(b=>/אשר/.test(b)),'ordinary approval card parks (tunnel sig never skips the user): '+JSON.stringify(cardC.btns));
 const dupC=await tunPost({id:'t6',kind:'run_command',ts,exp,sig:sigC,data:dataC});
 assert(dupC.status===409,'signed replay of a parked kind -> 409 at intake, original card intact');
 const cardC2=await card('echo tunnel-card-test');
 assert(cardC2&&cardC2.cid===cardC.cid,'original parked card untouched by the replay');

 // 15d) enroll_device: unsigned -> refused; worker-signed -> keypair generated ON the PC, pubkey acked
 pushCmd({id:'e0',kind:'enroll_device'});
 const aE0=await waitAck('e0','failed');
 assert(/unsigned/.test(aE0.note||''),'unsigned enroll refused: '+aE0.note);
 ts=Date.now();exp=EX();
 pushCmd({id:'e1',kind:'enroll_device',ts,exp,sig:sign('e1','enroll_device',ts,exp,'')});
 const aE1=await waitAck('e1','done');
 assert(aE1.result&&/^[0-9a-f]{16}$/.test(aE1.result.deviceId)&&aE1.result.pubkey,'enrolled: deviceId+pubkey acked');
 assert(!JSON.stringify(aE1.result).includes('priv'),'PRIVATE KEY NEVER travels');
 const devJ=JSON.parse(fs.readFileSync(cfg+'/glasswidgets/device/device.json','utf8'));
 assert(devJ.pub===aE1.result.pubkey&&devJ.priv,'device.json persisted locally with the private key');
 // health proof now live: server signs with the freshly enrolled key without a restart
 const hE=await (await fetch('http://127.0.0.1:47731/health?nonce=abc12345',{headers:{'X-GW-Key':'cmd-key'}})).json();
 assert(hE.deviceId===aE1.result.deviceId&&/^[0-9a-f]{128}$/.test(hE.sig||''),'health nonce signed by the enrolled device');
 const pubK=crypto.createPublicKey({key:Buffer.from(devJ.pub,'base64'),format:'der',type:'spki'});
 assert(crypto.verify(null,Buffer.from(hE.deviceId+'\nabc12345','utf8'),pubK,Buffer.from(hE.sig,'hex')),'sender-side verification of the health proof');

 // 15e) stage 1 has NO rotation: re-enroll returns the SAME identity, a tampered 'rotate' field
 // is IGNORED (it is not part of the signed payload and the code has no rotation path), and a
 // signed enroll replayed after a full RESTART still returns the same identity (never new keys)
 ts=Date.now();exp=EX();
 pushCmd({id:'e2',kind:'enroll_device',ts,exp,sig:sign('e2','enroll_device',ts,exp,'')});
 const aE2=await waitAck('e2','done');
 assert(aE2.result.deviceId===aE1.result.deviceId&&aE2.result.pubkey===aE1.result.pubkey,'re-enroll idempotent: same deviceId+pubkey, private never rewritten');
 ts=Date.now();exp=EX();
 pushCmd({id:'e3',kind:'enroll_device',rotate:true,ts,exp,sig:sign('e3','enroll_device',ts,exp,'')}); // tampered: rotate injected, not signed for
 const aE3=await waitAck('e3','done');
 assert(aE3.result.deviceId===aE1.result.deviceId&&aE3.result.pubkey===aE1.result.pubkey,'tampered rotate:true IGNORED - identity unchanged (stage 1 has no rotation)');
 await a.close();global.cmdRes=null;
 ({a,A}=await launch()); // RESTART: the replay must not mint new keys
 ts=Date.now();exp=EX();
 pushCmd({id:'e5',kind:'enroll_device',ts,exp,sig:sign('e5','enroll_device',ts,exp,'')});
 const aE5=await waitAck('e5','done');
 assert(aE5.result.deviceId===aE1.result.deviceId&&aE5.result.pubkey===aE1.result.pubkey,'enroll after restart returns the persisted identity');

 // 15g) /task + /info on the own server: PRIVATE reads (worker-signed, request-bound, replay-safe)
 // over durable ledger records - the direct-mode ack semantics. Records survive the 15e restart.
 const signRead=(p,q,dev,ts0)=>{const rts=ts0||Date.now(),rnonce=crypto.randomBytes(12).toString('base64url');
  const rsig=crypto.sign(null,Buffer.from(['GET',p,q,String(rts),rnonce,dev].join('\n'),'utf8'),PRIV).toString('hex');
  return {headers:{'X-GW-Key':'cmd-key','X-GW-Read-Ts':String(rts),'X-GW-Read-Nonce':rnonce,'X-GW-Read-Device':dev,'X-GW-Read-Sig':rsig},rts,rnonce}};
 const devPub=()=>crypto.createPublicKey({key:Buffer.from(aE1.result.pubkey,'base64'),format:'der',type:'spki'});
 const DEV_ID=aE1.result.deviceId;
 const shaH=t=>crypto.createHash('sha256').update(t,'utf8').digest('hex');
 const readJson=async(p,q)=>{const sr=signRead(p,q,DEV_ID);const r=await fetch('http://127.0.0.1:47731'+p+(q?'?'+q:''),{headers:sr.headers});const t=await r.text();
  const dsig=r.headers.get('x-gw-device-sig');
  return {status:r.status,body:(()=>{try{return JSON.parse(t)}catch{return null}})(),raw:t,dev:r.headers.get('x-gw-device'),dsig,
   // response verification: the device signature binds the RESPONSE to THIS REQUEST (device, method,
   // path, query, read ts+nonce, HTTP status, body hash) - a signed body can never be replayed
   verified:!!dsig&&r.headers.get('x-gw-device')===DEV_ID&&crypto.verify(null,Buffer.from([DEV_ID,'GET',p,q,String(sr.rts),sr.rnonce,String(r.status),shaH(t)].join('\n'),'utf8'),devPub(),Buffer.from(dsig,'hex'))}};
 // the public baked key alone is NOT enough for private reads
 assert((await fetch('http://127.0.0.1:47731/task?id=t2',{headers:{'X-GW-Key':'cmd-key'}})).status===403,'/task with only the public key -> 403');
 assert((await fetch('http://127.0.0.1:47731/info',{headers:{'X-GW-Key':'cmd-key'}})).status===403,'/info with only the public key -> 403');
 assert((await fetch('http://127.0.0.1:47731/task?id=t2')).status===403,'no key at all -> 403');
 const inf=await readJson('/info','');
 assert(inf.status===200&&inf.body.deviceId===aE1.result.deviceId&&inf.body.pubkey===aE1.result.pubkey,'/info self-describes the enrolled device');
 assert(inf.dev===aE1.result.deviceId&&inf.verified,'/info response is DEVICE-SIGNED over the request-bound canonical (device+method+path+query+ts+nonce+status+body hash)');
 const tT2=await readJson('/task','id=t2');
 assert(tT2.body.status==='done'&&tT2.body.terminal===true&&tT2.body.result&&Array.isArray(tT2.body.result.matches),'t2 terminal record via /task (survived restart)');
 assert(tT2.verified,'/task response is DEVICE-SIGNED over the request-bound canonical');
 // UNKNOWN-AFTER-RESTART: t6 was accepted (parked card) when the app last exited; the crash-safe
 // load marks it unknown - a final EVIDENCE state, never auto-retried
 const tT6=await readJson('/task','id=t6');
 assert(tT6.body.ok&&tT6.body.status==='unknown'&&tT6.body.terminal===true,'crashed-accepted t6 -> unknown (final): '+JSON.stringify(tT6.body));
 assert(tT6.verified,'unknown record response is device-signed too');
 // an unknown id still dedups: a signed replay of the SAME envelope -> 409, never re-executed
 {ts=Date.now();exp=EX();
  const dup=await tunPost({id:'t6',kind:'run_command',ts,exp,sig:sign('t6','run_command',ts,exp,JSON.stringify(dataC)),data:dataC});
  assert(dup.status===409,'replay of an unknown-record id -> 409 (never retried): '+dup.status)}
 // a 404 means the id was NEVER accepted: only then is it safe for the sender to create a NEW id
 {const nf=await readJson('/task','id=never');
  assert(nf.status===404&&nf.verified,'unknown task -> 404, device-signed (404 cannot be replayed onto another id)')}
 // device binding: a read signed for a DIFFERENT device -> 403
 {const sr=signRead('/task','id=t2','otherdevice0000');
  const r=await fetch('http://127.0.0.1:47731/task?id=t2',{headers:sr.headers});
  assert(r.status===403,'read bound to a different device -> 403 (cross-device collection closed)')}
 // read replay: the SAME signed read twice -> 403 (nonce replay-cached)
 {const sr=signRead('/task','id=t2',DEV_ID);
  const r1=await fetch('http://127.0.0.1:47731/task?id=t2',{headers:sr.headers});
  const r2=await fetch('http://127.0.0.1:47731/task?id=t2',{headers:sr.headers});
  assert(r1.status===200&&r2.status===403,'read replay with the same nonce -> 403')}
 // stale read ts -> 403
 {const sr=signRead('/task','id=t2',DEV_ID,Date.now()-120000);
  assert((await fetch('http://127.0.0.1:47731/task?id=t2',{headers:sr.headers})).status===403,'stale read ts -> 403')}
 // request binding: a signature for /info does not authorize /task
 {const sr=signRead('/info','',DEV_ID);
  assert((await fetch('http://127.0.0.1:47731/task?id=t2',{headers:sr.headers})).status===403,'signature bound to a different path -> 403')}

 // 15f) tunnel transport authority is enforced at EXECUTION time: a card approved AFTER the
 // envelope expired is refused - the command never runs
 ts=Date.now();exp=Date.now()+1500; // live at intake, dead by approval time
 const dataX={command:'echo SHOULD-NOT-RUN'};
 const sigX=sign('t7','run_command',ts,exp,JSON.stringify(dataX));
 const okX=await tunPost({id:'t7',kind:'run_command',ts,exp,sig:sigX,data:dataX});
 assert(okX.status===202,'short-lived signed envelope accepted at intake: '+JSON.stringify(okX));
 await card('SHOULD-NOT-RUN');
 await sleep(2200); // transport authority now expired (card TTL is 4000 - still parked)
 const stillThere=await A.evaluate(()=>[...document.querySelectorAll('#pillBody .card')].some(e=>e.textContent.includes('SHOULD-NOT-RUN')));
 assert(stillThere,'card still parked at approval time (inside the 1500..4000ms window)');
 await clickBtn('SHOULD-NOT-RUN','אשר');
 const aX=await waitAck('t7','failed');
 assert(/expired/.test(aX.note||''),'approval after transport expiry refused: '+aX.note);
 assert(!ACK.find(x=>x.id==='t7'&&x.status==='done'),'expired-transport command NEVER executed');
 logA=fs.readFileSync(cfg+'/glasswidgets/agent-audit.log','utf8');
 assert(/"stage":"transport_expired"/.test(logA),'transport expiry audited at execution time');

 await a.close();srv.close();
 console.log('AGENT-UI-TEST: ALL 10 SCENARIOS PASS');
 process.exit(0);
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
