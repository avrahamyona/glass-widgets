// Local computer-actions agent. Consumes commands from TWO intakes: the /glasswidgets/cmd SSE stream
// (worker fallback) and the embedded localhost server behind the tunnel (own-server leg), and runs
// allowlisted actions: find_files, get_file (upload via /file/upload), index, sys_info, screenshot,
// delete_file (Downloads folder only, files only), open_path, run_command, media_control, clipboard_read, web_task, ui_automation (screen clicks, card-gated), screenshot (read-only capture).
// Safety: a resolved-folder allowlist gates file reads, delete_file is pinned to the real Downloads
// folder, and every mutating/executing command lands in userData/agent-audit.log (JSON lines).
const fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto');
const {screen}=require('electron');
const {execFile,exec,execFileSync}=require('child_process');

const CAPS={maxDepth:10,maxScan:60000,contentBytes:2*1024*1024,uploadBytes:20*1024*1024,resultLen:3500,noteLen:500,cmdTimeoutMs:300000};
const SKIP_DIRS=new Set(['node_modules','.git','AppData','$Recycle.Bin','System Volume Information','.cache','.npm','.vscode','.config','Windows','Program Files','Program Files (x86)','ProgramData','$WinREAgent','Recovery','PerfLogs','.Trash']);
const TEXT_EXT=new Set(['.txt','.md','.csv','.json','.log','.xml','.html','.htm','.js','.ts','.py','.yaml','.yml','.ini','.rtf']);

function startAgent({app,rd,wr,chatKey,broadcastCard,broadcastSettle,updateApp,mediaCmd,islandCtl}){
 // lifecycle truth for approval cards: every terminal state is pushed to renderers so panels
 // settle on the EVENT, not on age guesses. outcome in: approved,denied,cancelled,executed,expired
 const settleCard=(cardId,outcome)=>{try{if(broadcastSettle)broadcastSettle(String(cardId||''),String(outcome||''))}catch{}};
 const cfg={...(rd('agent.json',{})||{})};
 const base=process.env.GLASSWIDGETS_CHAT_URL||'https://avi-music-account-staging.avi-music.workers.dev/glasswidgets/chat';
 const cmdUrl=process.env.GLASSWIDGETS_AGENT_CMD_URL||cfg.cmdUrl||base.replace(/\/chat$/,'/cmd/stream');
 const ackUrl=process.env.GLASSWIDGETS_AGENT_ACK_URL||cfg.ackUrl||base.replace(/\/chat$/,'/cmd/ack');
 const uploadUrl=process.env.GLASSWIDGETS_AGENT_UPLOAD_URL||cfg.uploadUrl||base.replace(/\/chat$/,'/file/upload');
 const CMD_KEY_BAKED='__GW_CMD_KEY__'; // CI replaces the placeholder from the GW_CMD_KEY secret; stays dormant when not injected
 const cmdKey=process.env.GLASSWIDGETS_AGENT_CMD_KEY||cfg.cmdKey||(CMD_KEY_BAKED.slice(0,5)==='__GW_'?'':CMD_KEY_BAKED);
 module.exports.cmdKey=cmdKey;
 const SIGN_PUB_BAKED='__GW_SIGN_PUB__'; // CI replaces the placeholder from the GW_SIGN_PUB secret (base64 DER spki of the worker's Ed25519 PUBLIC key); dormant when not injected. Asymmetric on purpose: nothing secret ships inside the public EXE, the signing private key exists only on the worker.
 const signPubB64=process.env.GLASSWIDGETS_AGENT_SIGN_PUB||cfg.signPub||(SIGN_PUB_BAKED.slice(0,5)==='__GW_'?'':SIGN_PUB_BAKED);
 let signPub=null;
 try{if(signPubB64)signPub=crypto.createPublicKey({key:Buffer.from(String(signPubB64).trim(),'base64'),format:'der',type:'spki'})}catch{}

 let folders=[];
 async function resolveFolders(){
  const list=process.env.GLASSWIDGETS_AGENT_FOLDERS?process.env.GLASSWIDGETS_AGENT_FOLDERS.split(',').map(s=>s.trim()).filter(Boolean)
   :(Array.isArray(cfg.folders)&&cfg.folders.length?cfg.folders:defaultRoots());
  function defaultRoots(){const r=[os.homedir()];
   if(process.platform==='win32')for(const c of 'CDEFGHIJKLMNOPQRSTUVWXYZ'){const d=c+':\\';try{if(fs.existsSync(d)&&!r.includes(d))r.push(d)}catch{}}
   return r}
  const out=[];
  for(const f of list){try{out.push(await fs.promises.realpath(f))}catch{}}
  folders=out;
 }
 async function inAllowlist(p){
  let rp=null;
  try{rp=await fs.promises.realpath(p)}catch{
   try{rp=path.join(await fs.promises.realpath(path.dirname(p)),path.basename(p))}catch{return null}
  }
  return folders.some(f=>rp===f||rp.startsWith(f+path.sep))?rp:null;
 }

 const auditFile=()=>path.join(app.getPath('userData'),'agent-audit.log');
 function audit(entry){try{fs.appendFileSync(auditFile(),JSON.stringify({at:new Date().toISOString(),...entry})+'\n')}catch{}}

 // delete_file: pinned to the REAL Downloads folder (realpath, traversal-proof), files only, never folders.
 // the degenerate downloads==homedir fallback (bare systems without a Downloads known-folder) is never accepted as a root
 async function downloadsRoots(){
  const out=[];
  for(const c of [app.getPath('downloads'),path.join(os.homedir(),'Downloads')]){
   try{const rp=await fs.promises.realpath(c);if(rp!==os.homedir()&&!out.includes(rp))out.push(rp)}catch{}}
  return out}
 async function deleteFile(id,p){
  const raw=String(p||'').trim();if(!raw)return ack(id,'failed','missing path');
  const roots=await downloadsRoots();if(!roots.length)return ack(id,'failed','no downloads folder');
  let rp;try{rp=await fs.promises.realpath(raw)}catch{return ack(id,'failed','not found')}
  if(!roots.some(dl=>rp.startsWith(dl+path.sep)))return ack(id,'failed','outside downloads - refused');
  let st;try{st=await fs.promises.lstat(rp)}catch{return ack(id,'failed','not found')}
  if(!st.isFile())return ack(id,'failed','not a file - refused');
  try{await fs.promises.unlink(rp)}catch(e){return ack(id,'failed',String(e&&e.code||e))}
  audit({kind:'delete_file',path:rp,bytes:st.size,ok:true});
  return ack(id,'done','deleted '+path.basename(rp),{path:rp,bytes:st.size});
 }

 // open_path: open a file or folder with the default app; gated by the same resolved-folder allowlist as reads
 async function openPathCmd(id,p){
  const raw=String(p||'').trim();if(!raw)return ack(id,'failed','missing path');
  const rp=await inAllowlist(raw)
  if(!rp)return ack(id,'failed','outside allowlist - refused');
  let err;
  if(process.platform==='win32'){const {shell}=require('electron');err=await Promise.race([shell.openPath(rp),new Promise(r=>setTimeout(()=>r('open timed out'),10000))])}
  else err=await new Promise(res=>{const t=setTimeout(()=>res('open timed out'),10000);execFile('xdg-open',[rp],{timeout:8000},e=>{clearTimeout(t);res(e?String(e.code||e.message||'open failed'):'')})}); // shell.openPath can wedge the main loop off-windows - always ack
  audit({kind:'open_path',path:rp,ok:!err,error:err||undefined});
  return err?ack(id,'failed',String(err).slice(0,200)):ack(id,'done','opened '+path.basename(rp),{path:rp});
 }

 // run_command: a shell command on the PC. Gated by the receiver key at the transport, a deny-list of
 // destructive verbs, a 60s timeout and a 1MB output cap; every run is audited with its output.
 const RUN_DENY=[/\bformat\s+[a-z]:/i,/\bshutdown\b/i,/\brestart-computer\b/i,/\brm\s+-[a-z]*r[a-z]*f\s+\//i,/\bdel\s+\/[a-z]*s/i,/\brd\s+\/[a-z]*s/i,/\brmdir\s+\/[a-z]*s/i,/\bdiskpart\b/i,/<\s*\w+\.(ps1|bat|cmd|exe)/i];
 function execRun(id,cmd){return new Promise(res=>{
  exec(cmd,{timeout:60000,maxBuffer:1024*1024,windowsHide:true},async(e,so,se)=>{
   // COMBINED envelope bound on the SERIALIZED result: the worker rejects result JSON >3500 / raw
   // body >4000. Fixed slices cannot guarantee that (escaping worst-case 6x), so we budget by actual
   // JSON.stringify length and record explicit truncation metadata.
   const so0=String(so||''),se0=String(se||(e&&e.message||'')),exitC=e?(e.code??null):0;
   const RES_CAP=3400; // leaves headroom under the worker's 3500 result cap
   const ser=(a,b)=>JSON.stringify({stdout:a,stderr:b,exit:exitC}).length;
   let stderr=se0.slice(0,800);
   if(ser('',stderr)>RES_CAP)stderr=stderr.slice(0,200); // pathological escaping in stderr alone
   let stdout=so0;
   while(stdout.length&&ser(stdout,stderr)>RES_CAP)stdout=stdout.slice(0,Math.floor(stdout.length*0.8));
   const result={stdout,stderr,exit:exitC};
   if(stdout.length<so0.length||stderr.length<se0.length){result.truncated=true;result.stdout_full=so0.length;result.stderr_full=se0.length}
   audit({kind:'run_command',stage:'executed',command:cmd,ok:!e,exit:exitC,stdout:stdout.slice(0,500),stderr:stderr.slice(0,300),truncated:!!result.truncated});
   await ack(id,e?'failed':'done',e?('exit '+(e.code??'?')):'ok',result);res();
  });
 })}

 // run_command NEVER executes on worker say-so: it parks as a pending approval, the island pops an
 // unmissable card with the exact command, and only the user's אשר tap runs it. Default deny after ~2 min.
 // Exception: PRE-APPROVED commands. When main/ops dispatch a command that answers an EXPLICIT user
 // instruction, the worker signs it (Ed25519 over id\nkind\nts\nexp\npayload; private key only on
 // the worker, public key baked at build time - nothing secret inside the public EXE).
 // A valid signature swaps the blocking card for an informational one that auto-executes after 5s
 // (cancelable) - so explicit instructions don't stall when he is away from the PC. A missing/invalid
 // signature falls back to the ordinary blocking card (fail-closed); an invalid one is also audited.
 const pendingApprovals=new Map(); // cardId -> {cmdId,kind,command,action,task,timer,pre,exp}
 const APPROVAL_TTL=+process.env.GLASSWIDGETS_APPROVAL_TTL_MS||120000;
 const PRE_TTL_MS=300000,AUTO_RUN_MS=+process.env.GLASSWIDGETS_AUTO_RUN_MS||5000;
 // Ed25519 pre-approval: the worker signs id\nkind\nts\nexp\npayload with its private key; the client
 // only verifies. Strict field formats, freshness AND an explicit expires_at (checked at receipt and
 // again before the auto-run timer fires). ANY anomaly -> ordinary blocking card (fail-closed).
 const SKEW_MS=60000; // small clock-skew allowance; ts further in the future is rejected
 function validPreapproval(m,payload,device){
  try{
   if(!signPub||!seenOk||!m||m.ts==null||m.exp==null)return false;
   const sig=String(m.sig||'');if(!/^[0-9a-f]{128}$/.test(sig))return false; // strict hex - never feed arbitrary bytes to verify
   const ts=+m.ts,exp=+m.exp,now=Date.now();
   if(!Number.isFinite(ts)||!Number.isFinite(exp))return false;
   if(ts>now+SKEW_MS||ts<now-PRE_TTL_MS)return false; // not from the future, not stale
   if(exp<=ts||exp-ts>PRE_TTL_MS||exp<=now)return false; // a sane, live validity window
   // v2 envelopes bind the TARGET DEVICE into the signature (device\nid\nkind...); v1 (stage A, single device) has no device field
   const fields=device!=null?[String(device),String(m.id),String(m.kind),String(ts),String(exp),payload]:[String(m.id),String(m.kind),String(ts),String(exp),payload];
   return crypto.verify(null,Buffer.from(fields.join('\n'),'utf8'),signPub,Buffer.from(sig,'hex'));
  }catch{return false}
 }
 // replay guard: signed command ids are remembered (persisted) with their decision until their exp,
 // so the same signed message cannot re-run after a burst, reconnect or app restart. The store is
 // load-bearing: if it cannot be read (corrupt) or written, signed auto-run is DISABLED (blocking
 // card instead) - never a pretend replay guard.
 const seenFile=()=>path.join(app.getPath('userData'),'agent-seen.json');
 const seen={};let seenOk=true;
 try{const j=JSON.parse(fs.readFileSync(seenFile(),'utf8'));for(const k of Object.keys(j))if(j[k]&&+j[k].exp>Date.now())seen[k]=j[k]}
 catch(e){if(!e||e.code!=='ENOENT')seenOk=false} // missing file is fine (first run); corrupt is not
 function markSeen(id,decision,exp){
  const sid=String(id),prev=seen[sid],now=Date.now();
  for(const k of Object.keys(seen))if(!(+seen[k].exp>now))delete seen[k]; // in-session pruning, not just at startup
  seen[sid]={at:now,exp:+(exp||(prev&&prev.exp)||now),decision};
  try{fs.writeFileSync(seenFile(),JSON.stringify(seen))}catch{
   if(prev)seen[sid]=prev;else delete seen[sid]; // roll back: a failed durable mark leaves no in-memory ghost
   seenOk=false;return false}
  return true;
 }
 // duplicate-id guard for BOTH branches: a reused id (signed or not) must never clobber a parked
 // approval entry - its original timer would otherwise execute the replacement without a click.
 function checkDup(id,kind,detail){
  // Duplicate delivery (worker retry): NEVER ack here - a dup ack races the original execution's
  // real result and can clobber it server-side. Audit only; the original flow's ack is authoritative.
  const sid=String(id),prev=seen[sid];
  if(prev){audit({kind,stage:'duplicate',command:detail&&detail.command,url:detail&&detail.url,decision:prev.decision});return true}
  for(const p of pendingApprovals.values())if(String(p.cmdId)===sid){
   audit({kind,stage:'duplicate',command:detail&&detail.command,url:detail&&detail.url,decision:'pending'});return true}
  return false;
 }
 function execPending(p){
  // execution-time transport authority, one gate for EVERY branch (auto-run, approval tap,
  // media session grant): the effect dies if either the signed exp or the transport expiry passed
  const expA=[+p.exp,+p.texp].filter(x=>Number.isFinite(x)&&x>0);
  if(expA.length&&Date.now()>=Math.min(...expA)){audit({kind:p.kind||'run_command',stage:'transport_expired',id:String(p.cmdId||'').slice(0,40),command:p.command,action:p.action});ack(p.cmdId,'failed','expired - תוקף סמכות התעבורה פג לפני הביצוע');return}
  if(ledger.transition(p.cmdId,'running')!==true){audit({kind:p.kind||'run_command',stage:'running_gate_fail',id:String(p.cmdId||'').slice(0,40)});ack(p.cmdId,'failed','ledger transition failed - effect blocked');return} // no durable running mark -> NO effect
  if(p.kind==='media_control'){mediaApproved=true;execMedia(p.cmdId,p.action);return}
  if(p.kind==='web_task'){execWebTask(p.cmdId,p.task);return}
  if(p.kind==='ui_automation'){execUi(p.cmdId,p.task.steps);return}
 if(p.kind==='island_control'){execIsland(p.cmdId,p.task.action);return}
  execRun(p.cmdId,p.command);
 }
 function runCommand(id,command,msg,intake){
  const cmd=String(command||'').trim();
  if(!cmd)return ack(id,'failed','missing command');
  if(cmd.length>1000)return ack(id,'failed','command too long');
  if(RUN_DENY.some(rx=>rx.test(cmd))){audit({kind:'run_command',stage:'denied',command:cmd,error:'guardrail'});return ack(id,'failed','command denied by guardrail')}
  if(checkDup(id,'run_command',{command:cmd}))return;
  if(pendingApprovals.size>=5)return ack(id,'failed','too many pending approvals');
  if(!broadcastCard)return ack(id,'failed','no UI for approvals');
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  if(msg&&validPreapproval(msg,cmd)){
   if(!markSeen(id,'pending',+msg.exp)){audit({kind:'run_command',stage:'seen_persist_failed',command:cmd})} // no durable replay guard -> blocking card below
   else{
    const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
     if(p.exp&&Date.now()>=p.exp){markSeen(p.cmdId,'expired');settleCard(cardId,'expired');audit({kind:p.kind,stage:'expired_pre',command:p.command});ack(p.cmdId,'failed','expired - החתימה פגה לפני הביצוע');return}
     markSeen(p.cmdId,'executed');audit({kind:p.kind,stage:'preapproved',command:p.command});settleCard(cardId,'executed');execPending(p)},AUTO_RUN_MS);
    timer.unref&&timer.unref();
    const cardExp=[+msg.exp,intake&&+intake.exp].filter(x=>Number.isFinite(x)&&x>0).reduce((a,b)=>Math.min(a,b),+msg.exp); // the card's private expiry is min(signed exp, transport authority) - the auto-run timer and the shared execPending gate both honor it
    pendingApprovals.set(cardId,{cmdId:id,kind:'run_command',command:cmd,timer,pre:true,exp:cardExp});
    audit({kind:'run_command',stage:'preapprove_card',command:cmd});
    broadcastCard({id:cardId,title:'⚡ מבצע פקודה שאישרת',expiresAt:+msg.exp,body:'השרת מבקש להריץ לפי ההוראה המפורשת שלך:\n'+cmd+'\n\nהפקודה רצה אוטומטית בעוד '+(AUTO_RUN_MS/1000)+' שניות - הקש בטל כדי לעצור.',buttons:[{id:'deny',label:'בטל',style:'danger'}]});
    return;
   }
  }
  if(msg&&msg.sig)audit({kind:'run_command',stage:'bad_sig',command:cmd});
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'run_command',stage:'expired',command:p.command});settleCard(cardId,'expired');ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'run_command',command:cmd,timer,texp:intake&&+intake.exp||0});
  audit({kind:'run_command',stage:'requested',command:cmd});
  broadcastCard({id:cardId,title:'⚠️ אישור הרצת פקודה במחשב',expiresAt:Date.now()+APPROVAL_TTL,body:'השרת מבקש להריץ:\n'+cmd+'\n\nבלי אישור - הפקודה תידחה אוטומטית בעוד כ-2 דקות.',buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
 }
 async function handleCardAction(p){
  const cardId=String(p&&p.card_id||''),pend=pendingApprovals.get(cardId);
  if(!pend)return {ok:false,reason:'expired'};
  pendingApprovals.delete(cardId);clearTimeout(pend.timer);
  if(p.button_id==='approve'){
   if(pend.texp&&Date.now()>=pend.texp){audit({kind:pend.kind||'run_command',stage:'transport_expired',command:pend.command,action:pend.action});settleCard(cardId,'expired');ack(pend.cmdId,'failed','expired - תוקף סמכות התעבורה פג לפני האישור');return {ok:true}} // transport authority is enforced at EXECUTION time, not just intake
   audit({kind:pend.kind||'run_command',stage:'approved',command:pend.command,action:pend.action});
   settleCard(cardId,'approved');execPending(pend);return {ok:true}}
  if(pend.pre)markSeen(pend.cmdId,'cancelled');
  audit({kind:pend.kind||'run_command',stage:pend.pre?'cancelled':'denied',command:pend.command,action:pend.action});
  settleCard(cardId,pend.pre?'cancelled':'denied');
  ack(pend.cmdId,'failed',pend.pre?'cancelled - המשתמש ביטל מהאי':'denied - המשתמש דחה מהאי');return {ok:true}}
 module.exports.handleCardAction=handleCardAction;

 // media_control: play/pause/toggle/next/prev via the Windows media bridge (SMTC). An island approval
 // card gates the CLASS once per app session (the user's approved stage); later commands in the session
 // run directly, every one audited. The bridge exposes no volume control - volume is out of scope.
 let mediaApproved=false;
 const MEDIA_ACTIONS=['toggle','play','pause','next','prev'];
 async function execMedia(id,a){
  if(!mediaCmd){audit({kind:'media_control',stage:'failed',action:a,error:'no bridge'});return ack(id,'failed','no media bridge in this build')}
  const r=mediaCmd(a);
  audit({kind:'media_control',stage:'executed',action:a,ok:!!(r&&r.ok),error:r&&r.error||undefined});
  return r&&r.ok?ack(id,'done',a):ack(id,'failed',String(r&&r.error||'media bridge unavailable').slice(0,200));
 }
 function mediaControl(id,action,intake){
  const a=String(action||'').trim().toLowerCase();
  if(!MEDIA_ACTIONS.includes(a))return ack(id,'failed','bad action');
  if(mediaApproved){audit({kind:'media_control',stage:'requested',action:a,via:'session-grant'});return execPending({cmdId:id,kind:'media_control',action:a,texp:intake&&+intake.exp||0})} // session grant is NOT a gate bypass: the same durable running transition decides, and the shared expiry gate gets the transport authority
  if(pendingApprovals.size>=5)return ack(id,'failed','too many pending approvals');
  if(!broadcastCard)return ack(id,'failed','no UI for approvals');
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'media_control',stage:'expired',action:p.action});settleCard(cardId,'expired');ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'media_control',action:a,timer,texp:intake&&+intake.exp||0});
  audit({kind:'media_control',stage:'requested',action:a});
  broadcastCard({id:cardId,title:'🎵 אישור שליטה במדיה',expiresAt:Date.now()+APPROVAL_TTL,body:'השרת מבקש שליטה בניגון במחשב (פעולה: '+a+'). אישור מתיר שליטה במדיה עד הפעלה מחדש של האפליקציה. בלי אישור - הבקשה תידחה אוטומטית בעוד כ-2 דקות.',buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
 }

 // clipboard_read: read-only - reports the PC clipboard text back to its owner (capped), no card.
 async function clipboardRead(id){
  const {clipboard}=require('electron');
  let t;try{t=clipboard.readText()||''}catch(e){audit({kind:'clipboard_read',ok:false,error:String(e&&e.message||e)});return ack(id,'failed','clipboard read failed')}
  audit({kind:'clipboard_read',chars:t.length});
  if(!t)return ack(id,'done','הלוח ריק',{text:'',chars:0});
  const CAP=2000,truncated=t.length>CAP;
  return ack(id,'done',t.length+' תווים בלוח',{text:truncated?t.slice(0,CAP):t,chars:t.length,truncated});
 }

 // web_task (stage 7 pilot): drive a HIDDEN Chromium window (the app's own Electron) on the PC -
 // no visible window, no physical mouse/keyboard, isolated persistent profile (persist:agent-web).
 // Hard bounds: https-only end to end; private/local destinations blocked by STRING and by DNS
 // RESOLUTION on every request of the task (main frame, redirects, subrequests); <=20 steps (a
 // bigger plan is rejected outright - never truncated, he reviews the complete plan on the card);
 // per-step timeouts + a hard 60s task timeout with teardown; the ack result is size-guaranteed.
 // ALWAYS behind an island approval card (per task, no session grant); every step audited.
 const WEB_ALLOW_LOCAL=process.env.GLASSWIDGETS_WEB_TASK_ALLOW_LOCAL==='1'; // test hook only - production stays https-only + no local targets
 function ipPublic(ip){
  ip=String(ip||'').toLowerCase().replace(/^\[|\]$/g,'');
  let mapped=ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); // IPv4-mapped IPv6, dotted form
  if(mapped)ip=mapped[1];
  else{const hex=ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/); // normalized hex form (::ffff:7f00:1)
   if(hex){const a=parseInt(hex[1],16),b=parseInt(hex[2],16);ip=(a>>8)+'.'+(a&255)+'.'+(b>>8)+'.'+(b&255)}}
  const m=ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if(m){const a=+m[1],b=+m[2],c=+m[3]; // every non-global v4 range, not just the common RFC1918 ones
   if(a===0||a===10||a===127||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||a>=224)return false;
   if(a===192&&(b===168||(b===0&&(c===0||c===2))))return false;
   if(a===198&&(b===18||b===19||(b===51&&c===100)))return false;
   if(a===203&&b===0&&c===113)return false;
   return true}
  return !(ip==='::1'||ip==='::'||/^(fe8|fe9|fea|feb|fc|fd|ff)/i.test(ip)||ip.startsWith('2001:db8'));
 }
 function webUrlOk(u){
  if(typeof u!=='string'||u.length>500)return false;
  if(!/^https:\/\/\S+$/i.test(u)&&!(WEB_ALLOW_LOCAL&&/^http:\/\/\S+$/i.test(u)))return false;
  if(WEB_ALLOW_LOCAL)return true;
  let h;try{h=new URL(u).hostname.toLowerCase()}catch{return false}
  if(h==='localhost'||h.endsWith('.localhost')||h.endsWith('.local')||h.endsWith('.internal')||h.endsWith('.lan')||h.endsWith('.home'))return false;
  if(/^[\d.]+$/.test(h)||h.includes(':'))return ipPublic(h);
  return true; // a public-looking name still has to survive the DNS check before any request goes out
 }
 // best-effort: Chromium resolves independently, so a rebinding attacker flipping DNS between our
 // check and Chromium's lookup is NOT fully barred - this narrows the window, it is not a hard guarantee.
 const dnsP=require('dns').promises;
 async function resolvesPublic(u,cache){
  if(WEB_ALLOW_LOCAL)return true;
  let h;try{h=new URL(u).hostname.toLowerCase()}catch{return false}
  if(/^[\d.]+$/.test(h)||h.includes(':'))return ipPublic(h); // literal already decided
  if(cache.has(h))return cache.get(h);
  let ok=false;
  try{const addrs=await dnsP.lookup(h,{all:true});
   ok=addrs.length>0&&addrs.every(a=>ipPublic(a.address))}catch{ok=false}
  cache.set(h,ok);return ok;
 }
 // one webRequest guard per agent-web session; consults the live task windows map so main-frame
 // loads, redirects AND subrequests of a task are all DNS-checked before they leave.
 const webTaskWindows=new Map(); // webContents.id -> {taskId,dnsCache}
 function ensureWebGuard(ses){
  if(ses.__gwWebGuard)return;ses.__gwWebGuard=true;
  ses.webRequest.onBeforeRequest({urls:['*://*/*']},(details,callback)=>{
   const ent=webTaskWindows.get(details.webContentsId);
   if(!ent){ // fail-closed: service workers, background fetches and post-cleanup stragglers on the dedicated agent-web session never go out
    audit({kind:'web_task',stage:'request_blocked',task:'-',url:String(details.url||'').slice(0,200),error:'unmapped source on guarded session'});
    return callback({cancel:true})}
   const u=String(details.url||'');
   (async()=>webUrlOk(u)&&await resolvesPublic(u,ent.dnsCache))()
    .then(ok=>{if(!ok)audit({kind:'web_task',stage:'request_blocked',task:ent.taskId,url:u.slice(0,200)});callback(ok?{}:{cancel:true})},
          ()=>{audit({kind:'web_task',stage:'request_blocked',task:ent.taskId,url:u.slice(0,200),error:'guard error'});callback({cancel:true})});
  });
 }
 function webTaskResultCap(out){
  // guarantee: the serialized ack result NEVER exceeds the worker's ~3,500-char limit
  const fits=()=>JSON.stringify(out).length<=2800;
  if(fits())return out;
  out.truncated=true;
  const texts=out.steps.filter(x=>typeof x.text==='string');
  for(const cap of [400,150,40]){for(const t of texts)if(t.text.length>cap)t.text=t.text.slice(0,cap)+'…';if(fits())return out}
  for(const t of texts)delete t.text;
  if(fits())return out;
  for(const st of out.steps){delete st.url;delete st.error} // long goto urls / errors go next
  if(fits())return out;
  const total=out.steps.length,ok=out.steps.filter(x=>x.ok).length;
  return {url:out.url,steps_total:total,steps_ok:ok,truncated:true}; // last resort: summary only, always small
 }
 async function execWebTask(id,task){
  const url=String(task.url||'').trim();
  if(!webUrlOk(url)){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'url refused (https-only, no local targets)'});return ack(id,'failed','url refused - https only, no private/local targets')}
  const steps=task.steps.slice(0,20);
  const {BrowserWindow,session}=require('electron');
  let win=null,timedOut=false;
  const out={url:url.slice(0,300),steps:[]};
  const stepAudit=(i,d,ok,err)=>audit({kind:'web_task',stage:'step',task:String(id).slice(0,60),step:i,do:d,ok:!!ok,error:err?String(err).slice(0,150):undefined});
  const body=async()=>{
   win=new BrowserWindow({show:false,width:1100,height:800,webPreferences:{sandbox:true,partition:'persist:agent-web'}});
   win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
   win.webContents.session.on('will-download',e=>e.preventDefault());
   ensureWebGuard(win.webContents.session);
   const ent={taskId:String(id).slice(0,60),dnsCache:new Map()};
   webTaskWindows.set(win.webContents.id,ent);
   win.on('closed',()=>webTaskWindows.delete(win.webContents.id));
   if(!WEB_ALLOW_LOCAL&&!(await resolvesPublic(url,ent.dnsCache)))throw new Error('destination resolves to a private/local address - refused');
   const js=(code)=>Promise.race([win.webContents.executeJavaScript(code),new Promise((_,rej)=>setTimeout(()=>rej(new Error('step timeout')),15000))]);
   const sel=x=>JSON.stringify(String(x||'').slice(0,200));
   await Promise.race([win.webContents.loadURL(url),new Promise((_,rej)=>setTimeout(()=>rej(new Error('load timeout')),20000))]);
   for(let i=0;i<steps.length;i++){
    if(timedOut)return;
    const st=steps[i],d=String(st.do||'').toLowerCase();
    try{
     if(d==='goto'){const u=String(st.url||'').slice(0,500);if(!webUrlOk(u))throw new Error('goto url refused');
      if(!WEB_ALLOW_LOCAL&&!(await resolvesPublic(u,ent.dnsCache)))throw new Error('goto destination resolves private - refused');
      await Promise.race([win.webContents.loadURL(u),new Promise((_,rej)=>setTimeout(()=>rej(new Error('goto timeout')),20000))]);out.steps.push({do:d,ok:true,url:u.slice(0,200)});}
     else if(d==='click'){const r=await js('(()=>{const el=document.querySelector('+sel(st.selector)+');if(!el)return false;el.click();return true})()');out.steps.push({do:d,ok:!!r});}
     else if(d==='type'){const r=await js('(()=>{const el=document.querySelector('+sel(st.selector)+');if(!el)return false;el.focus();el.value='+JSON.stringify(String(st.text||'').slice(0,500))+';el.dispatchEvent(new Event(\'input\',{bubbles:true}));el.dispatchEvent(new Event(\'change\',{bubbles:true}));return true})()');out.steps.push({do:d,ok:!!r});}
     else if(d==='wait'){await new Promise(r=>setTimeout(r,Math.min(Math.max(+st.ms||1000,100),10000)));out.steps.push({do:d,ok:true});}
     else if(d==='extract'){const t=await js('(()=>{const el=document.querySelector('+sel(st.selector||'body')+');return el?String(el.innerText||\'\').slice(0,1000):null})()');out.steps.push({do:d,ok:t!==null,text:t===null?undefined:t});}
     else if(d==='screenshot'){
      const img=await Promise.race([win.webContents.capturePage(),new Promise((_,rej)=>setTimeout(()=>rej(new Error('capture timeout')),15000))]);
      const buf=img.toPNG();
      const u=new URL(uploadUrl);u.searchParams.set('name','webtask-'+String(id).replace(/[^\w-]/g,'').slice(0,40)+'.png');
      const r=await fetch(u,{method:'POST',headers:{'content-type':'image/png','X-GW-Key':cmdKey},body:buf,signal:AbortSignal.timeout(30000)});
      if(!r.ok)throw new Error('upload '+r.status);
      const j=await r.json().catch(()=>({}));if(!j.file_id)throw new Error('upload bad response');
      out.steps.push({do:d,ok:true,file_id:String(j.file_id),bytes:buf.length});}
     else{out.steps.push({do:d||'?',ok:false,error:'unknown step'});stepAudit(i,d,false,'unknown step');continue}
     stepAudit(i,d,out.steps[out.steps.length-1].ok,out.steps[out.steps.length-1].error);
    }catch(se){out.steps.push({do:d,ok:false,error:String(se&&se.message||se).slice(0,150)});stepAudit(i,d,false,se&&se.message||se)}
   }
  };
  try{
   await Promise.race([body(),new Promise(res=>setTimeout(()=>{timedOut=true;if(win&&!win.isDestroyed())win.destroy();res()},60000))]);
   if(timedOut){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'hard task timeout 60s'});return ack(id,'failed','task timeout (60s hard limit)',webTaskResultCap(out))}
   audit({kind:'web_task',stage:'executed',url:url.slice(0,200),steps:out.steps.length,ok:out.steps.filter(x=>x.ok).length});
   return ack(id,'done','web task: '+out.steps.filter(x=>x.ok).length+'/'+out.steps.length+' steps ok',webTaskResultCap(out));
  }catch(e){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:String(e&&e.message||e).slice(0,200)});return ack(id,'failed',String(e&&e.message||'web task error').slice(0,200))}
  finally{
   if(win&&!win.isDestroyed())win.destroy();
   try{require('electron').session.fromPartition('persist:agent-web').clearStorageData({storages:['serviceworkers']})}catch{} // no persistent background execution outlives the task
  }
 }
 function webTaskPlan(url,steps){
  // the COMPLETE effective plan he approves: full goto urls, full type text - never truncated
  const lines=steps.map((st,i)=>{const d=String(st.do||'?').toLowerCase();
   if(d==='goto')return (i+1)+'. goto '+String(st.url||'');
   if(d==='click')return (i+1)+'. click '+String(st.selector||'');
   if(d==='type')return (i+1)+'. type '+String(st.selector||'')+' ← "'+String(st.text||'').slice(0,500)+'"'; // the effective text - the executor caps at 500 too
   if(d==='extract')return (i+1)+'. extract '+String(st.selector||'body');
   if(d==='screenshot')return (i+1)+'. screenshot';
   if(d==='wait')return (i+1)+'. wait '+Math.min(Math.max(+st.ms||1000,100),10000)+'ms';
   return (i+1)+'. '+d});
  return lines.join('\n');
 }
 async function webTask(id,task,intake){
  const url=String(task&&task.url||'').trim();
  if(!webUrlOk(url))return ack(id,'failed','url refused - https only, no private/local targets');
  const rawSteps=Array.isArray(task.steps)?task.steps:[];
  if(rawSteps.length>20){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'plan too long',steps:rawSteps.length});return ack(id,'failed','plan too long to review safely (max 20 steps) - rejected')}
  const plan=webTaskPlan(url,rawSteps);
  if(plan.length>1400){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'plan too long',chars:plan.length});return ack(id,'failed','plan too long to review safely ('+plan.length+' chars) - rejected')}
  const steps=rawSteps;
  const label=String(task.label||'').slice(0,200);
  // pre-approval payload the worker signs for web_task: url + "\n" + JSON.stringify(steps as sent)
  const pre=validPreapproval(task,url+'\n'+JSON.stringify(rawSteps));
  // duplicate guard + replay mark BEFORE the async DNS yield: a same-id copy arriving during the await
  // can never slip a replacement into the original's auto-run timer. preOk (signature AND a durable
  // replay mark) - not pre - decides which card copy is shown: a persistence failure falls back to
  // the BLOCKING copy, never an auto-run promise the guard cannot back.
  if(checkDup(id,'web_task',{url:url.slice(0,200)}))return;
  let preOk=false;
  if(pre){preOk=markSeen(id,'pending',+task.exp);if(!preOk)audit({kind:'web_task',stage:'seen_persist_failed',url:url.slice(0,200)})}
  if(!WEB_ALLOW_LOCAL&&!(await resolvesPublic(url,new Map()))){if(preOk)markSeen(id,'refused');audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'resolves private'});return ack(id,'failed','destination resolves to a private/local address - refused')}
  if(!preOk&&checkDup(id,'web_task',{url:url.slice(0,200)}))return; // post-yield: an unsigned same-id copy must not clobber the parked card
  // the card he approves must show the COMPLETE url+plan - never a truncated review. The overflow check
  // runs BEFORE any pending-slot registration, so a rejected plan never parks an invisible 2-min slot.
  const core='השרת מבקש לבצע משימת דפדפן נסתרת במחשב:'+(label?'\n'+label:'')+'\n'+url+(plan?'\n\nהצעדים:\n'+plan:'')+'\n\nהמשימה רצה ברקע בלבד ולא נוגעת במסך או בעכבר.';
  const body=core+(preOk?'\nמתבצע אוטומטית בעוד '+(AUTO_RUN_MS/1000)+' שניות - הקש בטל כדי לעצור.':'\nבלי אישור - תידחה אוטומטית בעוד כ-2 דקות.');
  if(body.length>1900){if(preOk)markSeen(id,'rejected');audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'review card overflow',chars:body.length});return ack(id,'failed','plan too long to review safely (card limit) - rejected')}
  if(pendingApprovals.size>=5){if(preOk)markSeen(id,'refused');return ack(id,'failed','too many pending approvals')}
  if(!broadcastCard){if(preOk)markSeen(id,'refused');return ack(id,'failed','no UI for approvals')}
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  if(preOk){
   const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
    if(p.exp&&Date.now()>=p.exp){markSeen(p.cmdId,'expired');settleCard(cardId,'expired');audit({kind:p.kind,stage:'expired_pre',url:p.task&&p.task.url});ack(p.cmdId,'failed','expired - החתימה פגה לפני הביצוע');return}
    markSeen(p.cmdId,'executed');audit({kind:'web_task',stage:'preapproved',url:p.task&&p.task.url});settleCard(cardId,'executed');execPending(p)},AUTO_RUN_MS);
   timer.unref&&timer.unref();
   const cardExp=[+task.exp,intake&&+intake.exp].filter(x=>Number.isFinite(x)&&x>0).reduce((a,b)=>Math.min(a,b),+task.exp); // min(signed exp, transport authority) - the auto-run timer and the shared execPending gate both honor it
   pendingApprovals.set(cardId,{cmdId:id,kind:'web_task',task:{url,steps},timer,pre:true,exp:cardExp});
   audit({kind:'web_task',stage:'preapprove_card',url:url.slice(0,200),steps:steps.length});
   broadcastCard({id:cardId,title:'⚡ מבצע משימת אתר שאישרת',expiresAt:+task.exp,body,buttons:[{id:'deny',label:'בטל',style:'danger'}]});
   return;
  }
  if(task.sig)audit({kind:'web_task',stage:'bad_sig',url:url.slice(0,200)});
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'web_task',stage:'expired',url:p.task&&p.task.url});settleCard(cardId,'expired');ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'web_task',task:{url,steps},timer,texp:intake&&+intake.exp||0});
  audit({kind:'web_task',stage:'requested',url:url.slice(0,200),steps:steps.length});
  broadcastCard({id:cardId,title:'🌐 אישור משימת אתר ברקע',expiresAt:Date.now()+APPROVAL_TTL,body,buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
 }


 // ui_automation: REAL screen input - PHYSICAL-PIXEL contract end to end. Steps carry physical
 // screen coordinates (same-scale screenshot image pixels map 1:1: click = origin + image pixel).
 // Each display's physical rect = Electron logical bounds * its scaleFactor; a click must land
 // inside ONE actual display - never the gap-filled bounding box - validated on rounded coords when
 // the command arrives and AGAIN right before each injection (displays can change mid-task).
 // ui-input.ps1 sets per-monitor DPI awareness so SetCursorPos receives physical px, then VERIFIES
 // the observed cursor position (3px tolerance); a refused or misplaced injection fails the step and
 // stops the plan. Steps report INJECTED, never "target hit": what was under the cursor is verified
 // by the screenshot loop, not claimed by the injector. A hard task deadline (default 120s) is
 // checked before every step; a wait or input past it never runs. The rest mirrors web_task: the
 // island card shows the COMPLETE plan, a worker Ed25519 pre-approval (payload = JSON.stringify
 // (steps as sent)) is reserved for tasks answering an explicit user instruction, duplicate-id +
 // persisted replay guards, per-step audit. GLASSWIDGETS_UI_DRYRUN is a test-only hook.
 const UI_ACTIONS=['click','dblclick','rclick','move','wait'];
 const UI_DRYRUN=process.env.GLASSWIDGETS_UI_DRYRUN==='1';
 const UI_PS1_SRC=path.join(__dirname,'ui-input.ps1');
 function uiPs1File(){ // app.asar is not a real filesystem for powershell -File: stage to a temp copy
  // (the same route main.js uses for ble-scan.ps1). Re-staged when the packaged script changes.
  const d=path.join(app.getPath('temp'),'glasswidgets-ps');fs.mkdirSync(d,{recursive:true});
  const f=path.join(d,'ui-input.ps1'),src=fs.readFileSync(UI_PS1_SRC,'utf8');
  try{if(fs.readFileSync(f,'utf8').replace(/^\ufeff/,'')===src)return f}catch{} // staged file carries a BOM - compare normalized
  fs.writeFileSync(f,'\ufeff'+src); // BOM so Windows PowerShell reads it as UTF-8
  return f;
 }
 const UI_TASK_MS=+process.env.GLASSWIDGETS_UI_TASK_MS||120000; // hard whole-task deadline
 function dipRect(d){ // one display's PHYSICAL-pixel rect from the OS conversion, never a hand-rolled multiply
  if(typeof screen.dipToScreenRect!=='function'){
   if(process.platform==='win32')throw new Error('dipToScreenRect unavailable - refusing to guess the physical transform'); // fail closed on Windows
   const sf=d.scaleFactor||1; // dev/test platforms only, where scaleFactor is 1
   return {x:Math.round(d.bounds.x*sf),y:Math.round(d.bounds.y*sf),w:Math.round(d.bounds.width*sf),h:Math.round(d.bounds.height*sf)};
  }
  const r=screen.dipToScreenRect(null,{x:d.bounds.x,y:d.bounds.y,width:d.bounds.width,height:d.bounds.height});
  return {x:r.x,y:r.y,w:r.width,h:r.height};
 }
 function uiDisplays(){ // physical-pixel rects, one entry per ACTUAL display; empty = conversion refused (fail closed)
  try{return screen.getAllDisplays().map(dipRect)}catch{return []}
 }
 // a Windows box that cannot convert refuses every plan (uiPointOk over the empty list) and every screenshot (dipRect throw)
 function uiPointOk(x,y){return uiDisplays().some(r=>x>=r.x&&x<r.x+r.w&&y>=r.y&&y<r.y+r.h)}
 function uiStepsOk(raw){
  if(!Array.isArray(raw)||!raw.length||raw.length>20)return false;
  for(const st of raw){if(!st||typeof st!=='object')return false;
   const d=String(st.do||'').toLowerCase();
   if(!UI_ACTIONS.includes(d))return false;
   if(d==='wait'){const ms=+st.ms;if(!Number.isFinite(ms)||ms<100||ms>10000)return false;continue}
   const x=Math.round(+st.x),y=Math.round(+st.y);
   if(!Number.isFinite(x)||!Number.isFinite(y)||!uiPointOk(x,y))return false}
  return true}
 function uiPlan(steps){return steps.map((st,i)=>{const d=String(st.do||'?').toLowerCase();
   if(d==='wait')return (i+1)+'. המתנה '+Math.round(+st.ms)+'ms';
   const he={click:'לחיצה',dblclick:'לחיצה כפולה',rclick:'לחיצת ימני',move:'הזזת עכבר'}[d]||d;
   return (i+1)+'. '+he+' ב-(x:'+Math.round(+st.x)+', y:'+Math.round(+st.y)+')'}).join('\n')}
 function uiStep(d,x,y,deadline){return new Promise(res=>{
  if(UI_DRYRUN)return res({ok:true,dry:true});
  if(process.platform!=='win32')return res({ok:false,error:'ui input is supported on Windows only'});
  let ps1;try{ps1=uiPs1File()}catch(e){audit({kind:'ui_automation',stage:'failed',error:'ps1 staging failed'});return res({ok:false,error:'ps1 staging failed'})}
  const remain=deadline-Date.now(); // staging is synchronous - recompute AFTER it, right before launch
  if(remain<=0)return res({ok:false,error:'task deadline expired during staging',deadline:true});
  execFile('powershell',['-NoP','-NonI','-ExecutionPolicy','Bypass','-File',ps1,'-X',String(x),'-Y',String(y),'-Action',d],{timeout:Math.max(1,Math.floor(Math.min(10000,remain))),windowsHide:true},
   (e,so,se)=>res(e?{ok:false,error:String(se||so||e.message||e).replace(/\s+/g,' ').trim().slice(0,150)}:{ok:true}));
 })}
 async function execUi(id,steps){
  const out={steps:[],coord:'physical'};const deadline=Date.now()+UI_TASK_MS;
  const blow=i=>{out.deadline=true;audit({kind:'ui_automation',stage:'deadline',task:String(id).slice(0,60),step:i})};
  for(let i=0;i<steps.length;i++){
   let remain=deadline-Date.now();
   if(remain<=0){blow(i);break} // stop BEFORE the next step
   const st=steps[i],d=String(st.do||'').toLowerCase();
   if(d==='wait'){const ms=Math.round(+st.ms);
    if(ms>remain){blow(i);break} // a wait that would cross the deadline never starts
    await new Promise(r=>setTimeout(r,ms));
    if(Date.now()>deadline){blow(i);break}
    out.steps.push({do:d,ok:true});
    audit({kind:'ui_automation',stage:'step',task:String(id).slice(0,60),step:i,do:d,ok:true});continue}
   const x=Math.round(+st.x),y=Math.round(+st.y);
   if(!uiPointOk(x,y)){out.steps.push({do:d,x,y,ok:false,error:'point no longer inside a display'});
    audit({kind:'ui_automation',stage:'step',task:String(id).slice(0,60),step:i,do:d,x,y,ok:false,error:'pre-exec revalidation failed'});break}
   remain=deadline-Date.now(); // recomputed AFTER revalidation
   if(remain<=0){blow(i);break}
   const r=await uiStep(d,x,y,deadline); // the subprocess never outlives the task budget - exact remaining, rechecked after staging
   if(r.deadline){blow(i);break} // the budget expired inside staging - no injection happened
   if(Date.now()>deadline){out.steps.push({do:d,x,y,ok:!!r.ok,injected:!!r.ok,late:true});blow(i);break} // completed past the deadline: not a success
   out.steps.push({do:d,x,y,ok:r.ok,injected:!!r.ok,...(r.error?{error:r.error}:{}),...(r.dry?{dry:true}:{})});
   audit({kind:'ui_automation',stage:'step',task:String(id).slice(0,60),step:i,do:d,x,y,injected:!!r.ok,error:r.error});
   if(!r.ok)break; // stop at the first failed injection - never keep clicking blind
  }
  const ok=out.steps.filter(s=>s.ok).length;
  audit({kind:'ui_automation',stage:'executed',task:String(id).slice(0,60),steps:out.steps.length,ok,deadline:!!out.deadline});
  if(ok===steps.length&&!out.deadline)return ack(id,'done','ui: '+ok+'/'+steps.length+' inputs injected',out);
  return ack(id,'failed','ui: stopped ('+ok+'/'+steps.length+' injected'+(out.deadline?', task deadline':'')+') - injection is not target success, verify by screenshot',out);
 }
 function uiAutomation(id,m,intake){
  const rawSteps=Array.isArray(m.steps)?m.steps:[];
  if(!uiStepsOk(rawSteps)){audit({kind:'ui_automation',stage:'failed',error:'bad plan',steps:rawSteps.length});return ack(id,'failed','bad ui plan - unknown action, out-of-screen coords or >20 steps')}
  const steps=rawSteps,plan=uiPlan(steps),label=String(m.label||'').slice(0,200);
  // pre-approval payload the worker signs for ui_automation: JSON.stringify(steps as sent)
  const pre=validPreapproval(m,JSON.stringify(rawSteps));
  if(checkDup(id,'ui_automation',{}))return;
  let preOk=false;
  if(pre){preOk=markSeen(id,'pending',+m.exp);if(!preOk)audit({kind:'ui_automation',stage:'seen_persist_failed'})}
  // the card he approves shows the COMPLETE plan - every action with its exact coordinates
  const core='השרת מבקש לבצע לחיצות אמיתיות על המסך:'+(label?'\n'+label:'')+'\n\nהצעדים:\n'+plan+'\n\nהעכבר יזוז וילחץ על המסך לפי הרשימה בלבד.';
  const body=core+(preOk?'\nמתבצע אוטומטית בעוד '+(AUTO_RUN_MS/1000)+' שניות - הקש בטל כדי לעצור.':'\nבלי אישור - תידחה אוטומטית בעוד כ-2 דקות.');
  if(body.length>1900){if(preOk)markSeen(id,'rejected');audit({kind:'ui_automation',stage:'failed',error:'review card overflow',chars:body.length});return ack(id,'failed','plan too long to review safely (card limit) - rejected')}
  if(pendingApprovals.size>=5){if(preOk)markSeen(id,'refused');return ack(id,'failed','too many pending approvals')}
  if(!broadcastCard){if(preOk)markSeen(id,'refused');return ack(id,'failed','no UI for approvals')}
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  if(preOk){
   const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
    if(p.exp&&Date.now()>=p.exp){markSeen(p.cmdId,'expired');settleCard(cardId,'expired');audit({kind:p.kind,stage:'expired_pre'});ack(p.cmdId,'failed','expired - החתימה פגה לפני הביצוע');return}
    markSeen(p.cmdId,'executed');audit({kind:'ui_automation',stage:'preapproved',steps:p.task.steps.length});settleCard(cardId,'executed');execPending(p)},AUTO_RUN_MS);
   timer.unref&&timer.unref();
   const cardExp=[+m.exp,intake&&+intake.exp].filter(x=>Number.isFinite(x)&&x>0).reduce((a,b)=>Math.min(a,b),+m.exp); // min(signed exp, transport authority)
   pendingApprovals.set(cardId,{cmdId:id,kind:'ui_automation',task:{steps},timer,pre:true,exp:cardExp});
   audit({kind:'ui_automation',stage:'preapprove_card',steps:steps.length});
   broadcastCard({id:cardId,title:'⚡ מבצע לחיצות שאישרת',expiresAt:+m.exp,body,buttons:[{id:'deny',label:'בטל',style:'danger'}]});
   return;
  }
  if(m.sig)audit({kind:'ui_automation',stage:'bad_sig'});
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'ui_automation',stage:'expired'});settleCard(cardId,'expired');ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'ui_automation',task:{steps},timer,texp:intake&&+intake.exp||0});
  audit({kind:'ui_automation',stage:'requested',steps:steps.length});
  broadcastCard({id:cardId,title:'🖱️ אישור לחיצות על המסך',expiresAt:Date.now()+APPROVAL_TTL,body,buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
 }
 // island_control: open/close the chat island pill directly (no screen clicks needed - the pill
 // is click-through when closed, so OS-level injection can't reach it). Card/signed gated like ui_automation.
 const ISLAND_ACTIONS=['open','close']; // explicit allowlist - no inherited-object keys
 const ISLAND_ACTION_LABELS={open:'פתיחת האי',close:'סגירת האי'};
 async function execIsland(id,action){
  if(!islandCtl){audit({kind:'island_control',stage:'failed',error:'no island bridge in this build'});return ack(id,'failed','island_control unsupported in this build')}
  let r;try{r=await islandCtl(action)}catch(e){r={ok:false,error:String(e&&e.message||e)}}
  if(r&&r.ok)audit({kind:'island_control',stage:'executed',action});else audit({kind:'island_control',stage:'failed',action,error:(r&&r.error)||'unknown'});
  ack(id,r&&r.ok?'done':'failed',r&&r.ok?'done (renderer confirmed '+(action==='close'?'closed':action)+')':String((r&&r.error)||'unknown'));
 }
 function islandControl(id,m,intake){
  const action=String(m.action||'').toLowerCase();
  if(!ISLAND_ACTIONS.includes(action)){audit({kind:'island_control',stage:'failed',error:'bad action'});return ack(id,'failed','unknown island action (open/close)')}
  // pre-approval payload the worker signs for island_control: the action string
  const pre=validPreapproval(m,action);
  if(checkDup(id,'island_control',{}))return;
  let preOk=false;
  if(pre){preOk=markSeen(id,'pending',+m.exp);if(!preOk)audit({kind:'island_control',stage:'seen_persist_failed'})}
  const core='השרת מבקש לבצע על האי: '+ISLAND_ACTION_LABELS[action]+'.';
  const body=core+(preOk?'\nמתבצע אוטומטית בעוד '+(AUTO_RUN_MS/1000)+' שניות - הקש בטל כדי לעצור.':'\nבלי אישור - תידחה אוטומטית בעוד כ-2 דקות.');
  if(pendingApprovals.size>=5){if(preOk)markSeen(id,'refused');return ack(id,'failed','too many pending approvals')}
  if(!broadcastCard){if(preOk)markSeen(id,'refused');return ack(id,'failed','no UI for approvals')}
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  if(preOk){
   const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
    if(p.exp&&Date.now()>=p.exp){markSeen(p.cmdId,'expired');settleCard(cardId,'expired');audit({kind:p.kind,stage:'expired_pre'});ack(p.cmdId,'failed','expired - החתימה פגה לפני הביצוע');return}
    markSeen(p.cmdId,'executed');audit({kind:'island_control',stage:'preapproved',action:p.task.action});settleCard(cardId,'executed');execPending(p)},AUTO_RUN_MS);
   timer.unref&&timer.unref();
   const cardExp=[+m.exp,intake&&+intake.exp].filter(x=>Number.isFinite(x)&&x>0).reduce((a,b)=>Math.min(a,b),+m.exp); // min(signed exp, transport authority)
   pendingApprovals.set(cardId,{cmdId:id,kind:'island_control',task:{action},timer,pre:true,exp:cardExp});
   audit({kind:'island_control',stage:'preapprove_card',action});
   broadcastCard({id:cardId,title:'⚡ מבצע פעולת אי שאישרת',expiresAt:+m.exp,body,buttons:[{id:'deny',label:'בטל',style:'danger'}]});
   return;
  }
  if(m.sig)audit({kind:'island_control',stage:'bad_sig'});
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'island_control',stage:'expired'});settleCard(cardId,'expired');ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'island_control',task:{action},timer,texp:intake&&+intake.exp||0});
  audit({kind:'island_control',stage:'requested',action});
  broadcastCard({id:cardId,title:'🏝️ אישור פעולה על האי',expiresAt:Date.now()+APPROVAL_TTL,body,buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
 }

 // screenshot: read-only full-screen capture of the PRIMARY display at its physical pixel size,
 // uploaded to the worker as a PNG (same channel as get_file / web_task). FAILS CLOSED when the
 // primary display's capture source cannot be matched - never returns a different screen carrying
 // primary geometry. No approval card (read-only, like clipboard_read); every capture is audited.
 // The ack carries the display's physical origin + scale so image pixels map 1:1 onto ui_automation
 // physical coordinates: click_x = origin_x + img_x, click_y = origin_y + img_y.
 async function screenshotCmd(id){
  try{
   const {desktopCapturer}=require('electron');
   const prim=screen.getPrimaryDisplay(),sf=prim.scaleFactor||1,pr=dipRect(prim); // OS-converted physical rect
   const w=Math.max(1,pr.w),h=Math.max(1,pr.h);
   const srcs=await desktopCapturer.getSources({types:['screen'],thumbnailSize:{width:w,height:h}});
   const src=(srcs||[]).find(s=>String(s.display_id)===String(prim.id));
   if(!src){audit({kind:'screenshot',stage:'failed',error:'primary source not found'});return ack(id,'failed','primary display source not found - refused to guess')}
   const sz=src.thumbnail.getSize();
   if(!sz.width||!sz.height){audit({kind:'screenshot',stage:'failed',error:'empty capture'});return ack(id,'failed','empty capture')}
   const ox=pr.x,oy=pr.y;
   const rx=w/sz.width,ry=h/sz.height,oneToOne=sz.width===w&&sz.height===h; // measured, never assumed
   const buf=src.thumbnail.toPNG();
   const u=new URL(uploadUrl);u.searchParams.set('name','screenshot-'+String(id).replace(/[^\w-]/g,'').slice(0,40)+'.png');
   const r=await fetch(u,{method:'POST',headers:{'content-type':'image/png','X-GW-Key':cmdKey},body:buf,signal:AbortSignal.timeout(30000)});
   if(!r.ok)return ack(id,'failed','upload '+r.status);
   const j=await r.json().catch(()=>({}));if(!j.file_id)return ack(id,'failed','upload bad response');
   audit({kind:'screenshot',stage:'captured',bytes:buf.length,width:sz.width,height:sz.height});
   return ack(id,'done','screenshot '+sz.width+'x'+sz.height,{file_id:String(j.file_id),bytes:buf.length,img_width:sz.width,img_height:sz.height,origin_x:ox,origin_y:oy,logical_width:prim.size.width,logical_height:prim.size.height,scale:sf,display_id:String(prim.id),px_per_img_x:rx,px_per_img_y:ry,one_to_one:oneToOne,coord:oneToOne?'physical: click = origin + image pixel':'physical: click = origin + image pixel * px_per_img'});
  }catch(e){audit({kind:'screenshot',stage:'failed',error:String(e&&e.message||e)});return ack(id,'failed','screenshot error')}
 }

 // update_app: the ONLY pre-authorized mutating command (the user's standing grant: app updates install
 // automatically, without asking). No island card - that would contradict the grant. Everything else
 // that mutates stays behind the approval card / allowlists.
 async function updateAppCmd(id){
  audit({kind:'update_app',stage:'requested'});
  if(!updateApp)return ack(id,'failed','no updater in this build');
  try{
   const r=await updateApp(); // {ok,note,version?} - main.js owns electron-updater
   audit({kind:'update_app',stage:r.ok?'installing':'failed',note:String(r.note||'').slice(0,200),version:r.version||null});
   return ack(id,r.ok?'done':'failed',String(r.note||'').slice(0,300),r.version?{version:r.version}:undefined);
  }catch(e){audit({kind:'update_app',stage:'failed',error:String(e&&e.message||e)});return ack(id,'failed','updater error')}
 }

 // Transmit-time envelope invariant - enforced, never assumed: result JSON <=3500 AND the full raw
 // body (key/id/note included) <=3900. Shrink result.stdout when available (metadata preserved);
 // otherwise bound the note contribution and stub the result; a still-oversize body is audited, not sent blind.
 function fitAckBody(body){
  const RES_MAX=3500,BODY_MAX=3900;
  const ok=()=>{const w=JSON.stringify(body);return w.length<=BODY_MAX&&(!body.result||JSON.stringify(body.result).length<=RES_MAX)};
  if(ok())return JSON.stringify(body);
  const r=body.result;
  if(r&&typeof r.stdout==='string'){
   if(!r.stdout_full)r.stdout_full=String(r.stdout).length;
   while(r.stdout.length&&!ok())r.stdout=r.stdout.slice(0,Math.floor(r.stdout.length*0.8));
   r.truncated=true;
  }
  if(!ok()){
   body.note=String(body.note||'').slice(0,200); // the note/id/key share of the envelope is bounded explicitly
   body.result={truncated:true,guard:true};
   if(!ok()){audit({kind:'ack',stage:'envelope_fail',id:String(body.id||''),status:body.status,bytes:JSON.stringify(body).length});return null} // unfittable: audited and NEVER transmitted blind
  }
  return JSON.stringify(body);
 }
 async function ack(id,status,note,result){
  // ONE canonical result for BOTH the durable record and the wire: matches-trim (entry loss
  // always marked) bounded to RESULT_CAP bytes, stdout/stderr shrink with metadata preserved,
  // capResult as the backstop. A cached replay therefore serves EXACTLY what the original ack
  // carried - no dual fidelity.
  let canon;
  if(result!==undefined){
   let r,ser=true;try{r=JSON.parse(JSON.stringify(result))}catch{ser=false} // cycles / BigInt / throwing toJSON never crash the ack path
   if(!ser)r={unserializable:true};
   else if(r===null||typeof r!=='object')r={value:r}; // null and primitives get a stable object shape
   if(Array.isArray(r.matches)){const m=[...r.matches],fullCount=m.length; // trim WITH the loss metadata counted in, so the final object still fits the cap
    let sj=JSON.stringify({...r,matches:m,truncated:true,matches_full:fullCount});
    while(m.length&&Buffer.byteLength(sj)>RESULT_CAP){m.pop();sj=JSON.stringify({...r,matches:m,truncated:true,matches_full:fullCount})}
    r={...r,matches:m};if(m.length<fullCount){r.truncated=true;r.matches_full=fullCount}}
   if(typeof r.stdout==='string'||typeof r.stderr==='string'){ // stdout/stderr shrink, metadata preserved
    if(r.stdout_full==null)r.stdout_full=String(r.stdout||'').length;
    if(r.stderr_full==null)r.stderr_full=String(r.stderr||'').length;
    let sj=JSON.stringify(r);
    while(Buffer.byteLength(sj)>RESULT_CAP&&((r.stdout||'').length||(r.stderr||'').length)){
     if(String(r.stdout||'').length>=String(r.stderr||'').length)r.stdout=r.stdout.slice(0,Math.floor(r.stdout.length*0.7));
     else r.stderr=r.stderr.slice(0,Math.floor(r.stderr.length*0.7));
     r.truncated=true;sj=JSON.stringify(r)}
   }
   canon=capResult(r); // backstop for any other oversize shape
  }
  try{if(ledger.has(id)&&ledger.put(id,{status,note,result:canon})!==true)audit({kind:'ack',stage:'ledger_fail',id:String(id||''),status})}catch(e){audit({kind:'ack',stage:'ledger_fail',id:String(id||''),status})} // a terminal that cannot persist is AUDITED (evidence for reconciliation), never silently dropped
  const body={key:cmdKey,id:String(id||''),status,note:String(note||'').slice(0,CAPS.noteLen)};
  if(canon!==undefined)body.result=canon;
  const wire=fitAckBody(body);
  if(wire==null)return; // fitAckBody already audited envelope_fail - the fetch must not happen
  try{const r=await fetch(ackUrl,{method:'POST',headers:{'content-type':'application/json'},body:wire,signal:AbortSignal.timeout(15000)});
   const respText=await r.text().catch(()=> '');
   if(!r.ok){audit({kind:'ack',stage:'http_error',id:String(id||''),status,http:r.status,body:String(respText).slice(0,200)});return} // a rejected ack is EVIDENCE, never a silent drop
   let landed=null;try{landed=JSON.parse(respText).updated}catch{}
   if(landed!==1)audit({kind:'ack',stage:'ack_unconfirmed',id:String(id||''),status,http:r.status,updated:landed}); // 2xx without a row transition is not proof of landing
  }catch(e){audit({kind:'ack',stage:'send_failed',id:String(id||''),status,error:String(e&&e.message||e).slice(0,200)})}
 }

 async function walk(dir,depth,terms,hits,state){
  if(depth>CAPS.maxDepth||state.scanned>=CAPS.maxScan||Date.now()>state.deadline)return;
  let ents;try{ents=await fs.promises.readdir(dir,{withFileTypes:true})}catch{return}
  for(const e of ents){
   if(state.scanned>=CAPS.maxScan||Date.now()>state.deadline)return;
   const full=path.join(dir,e.name);
   if(e.isDirectory()){if(!SKIP_DIRS.has(e.name)&&!e.name.startsWith('.'))await walk(full,depth+1,terms,hits,state);continue}
   if(!e.isFile())continue;
   state.scanned++;
   const low=e.name.toLowerCase();
   if(terms.every(t=>low.includes(t))){try{const st=await fs.promises.stat(full);hits.push({path:full,name:e.name,size:st.size,modified:Math.round(st.mtimeMs)})}catch{}continue}
   if(state.contentLeft>0&&TEXT_EXT.has(path.extname(e.name).toLowerCase())){
    try{const st=await fs.promises.stat(full);if(st.size>0&&st.size<=CAPS.contentBytes){
     state.contentLeft--;const txt=await fs.promises.readFile(full,'utf8');const tl=txt.toLowerCase();
     if(terms.every(t=>tl.includes(t)))hits.push({path:full,name:e.name,size:st.size,modified:Math.round(st.mtimeMs)})}}catch{}}
  }
 }

 async function findFiles(id,query,limit,folder){
  const terms=String(query||'').toLowerCase().split(/\s+/).filter(t=>t.length>=2).slice(0,5);
  if(!terms.length)return ack(id,'failed','bad query');
  const lim=Math.min(Math.max(1,+limit||10),20);
  if(!folder){try{const fi=require('./fileindex');if(fi.ready()){
   const hits=fi.search(query,lim);if(hits.length)return ack(id,'done',hits.length+' matches',{matches:hits.map(m=>({path:m.path,name:m.name,size:m.size,modified:m.modified}))});
  }}catch{}}
  let roots=folders,scope='';
  if(folder){
   let rf=null;try{rf=await fs.promises.realpath(String(folder))}catch{}
   if(!rf)return ack(id,'failed','folder not found');
   try{if(!(await fs.promises.stat(rf)).isDirectory())return ack(id,'failed','not a folder')}catch{return ack(id,'failed','not a folder')}
   roots=[rf];scope=' in '+rf;
  }
  const hits=[],state={scanned:0,contentLeft:400,deadline:Date.now()+60000};
  for(const f of roots)await walk(f,0,terms,hits,state);
  hits.sort((a,b)=>b.modified-a.modified);
  const matches=hits.slice(0,lim);
  await ack(id,'done',(matches.length?matches.length+' matches':'no matches')+scope,{matches});
 }

 const MIME={'.pdf':'application/pdf','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.txt':'text/plain','.md':'text/markdown','.csv':'text/csv','.json':'application/json','.zip':'application/zip','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','.pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation','.mp3':'audio/mpeg','.mp4':'video/mp4'};
 function fmtGB(n){return (n/1073741824).toFixed(1)+'GB'}
 async function sysInfo(id,topic){
  topic=String(topic||'all').toLowerCase();
  const out={};const lines=[];
  if(topic==='screens'||topic==='all'){
   const ds=screen.getAllDisplays(),prim=screen.getPrimaryDisplay();
   out.screens=ds.map(d=>({id:d.id,width:d.size.width,height:d.size.height,primary:d.id===prim.id}));
   lines.push(ds.length+' מסכים מחוברים: '+out.screens.map(s=>s.width+'x'+s.height+(s.primary?' (ראשי)':'')).join(', '));
  }
  if(topic==='disk'||topic==='all'){
   try{const root=process.platform==='win32'?(process.env.SystemDrive||'C:')+'\\':'/';
    const st=fs.statfsSync(root);const free=st.bavail*st.bsize,total=st.blocks*st.bsize;
    out.disk={free_bytes:free,total_bytes:total};
    lines.push('מקום פנוי בכונן: '+fmtGB(free)+' מתוך '+fmtGB(total));
   }catch{lines.push('לא הצלחתי לקרוא את מצב הדיסק')}
  }
  if(topic==='processes'||topic==='all'){
   try{
    const list=await new Promise((res,rej)=>{
     if(process.platform==='win32')execFile('tasklist',['/fo','csv','/nh'],{timeout:8000},(e,so)=>{if(e)return rej(e);
      res(so.split('\n').map(l=>{const m=l.match(/"([^"]*)","[^"]*","[^"]*","[^"]*","([\d.,]+) K"/);return m?{name:m[1],mem_mb:Math.round(parseFloat(m[2].replace(/[.,]/g,''))/1024)}:null}).filter(Boolean))});
     else execFile('ps',['-eo','comm,rss','--sort=-rss'],{timeout:8000},(e,so)=>{if(e)return rej(e);
      res(so.split('\n').slice(1).map(l=>{const p=l.trim().split(/\s+/);return p.length>=2?{name:p[0],mem_mb:Math.round(+p[1]/1024)}:null}).filter(Boolean))});
    });
    const top=list.filter(x=>x.mem_mb>0).sort((a,b)=>b.mem_mb-a.mem_mb).slice(0,10);
    out.processes=top;
    lines.push('תהליכים גדולים: '+top.map(p=>p.name+' '+p.mem_mb+'MB').join(', '));
   }catch{lines.push('לא הצלחתי לקרוא את רשימת התהליכים')}
  }
  if(!lines.length)return ack(id,'failed','unknown topic');
  await ack(id,'done',lines.join('\n'),out);
 }

 async function getFile(id,p){
  const rp=await inAllowlist(String(p||''));
  if(!rp)return ack(id,'failed','denied');
  let st;try{st=await fs.promises.stat(rp)}catch{return ack(id,'failed','not found')}
  if(!st.isFile())return ack(id,'failed','not found');
  if(st.size>CAPS.uploadBytes)return ack(id,'failed','too large');
  try{
   const data=await fs.promises.readFile(rp);
   const u=new URL(uploadUrl);u.searchParams.set('name',path.basename(rp).slice(0,100));
   const r=await fetch(u,{method:'POST',headers:{'content-type':MIME[path.extname(rp).toLowerCase()]||'application/octet-stream','X-GW-Key':cmdKey},body:data,signal:AbortSignal.timeout(90000)});
   if(!r.ok)return ack(id,'failed','upload '+r.status);
   const j=await r.json().catch(()=>({}));
   if(!j.file_id)return ack(id,'failed','upload bad response');
   await ack(id,'done','uploaded',{file_id:String(j.file_id)});
  }catch{await ack(id,'failed','upload error')}
 }

 async function buildIndex(id){
  try{
   const fi=require('./fileindex');
   let roots=['Desktop','Documents','Downloads'].map(d=>path.join(os.homedir(),d));
   if(process.platform==='win32')for(const c of 'CDEFGHIJKLMNOPQRSTUVWXYZ'){const d=c+':\\';try{if(fs.existsSync(d)&&!roots.includes(d))roots.push(d)}catch{}}
   if(process.env.GLASSWIDGETS_AGENT_INDEX_ROOTS)roots=process.env.GLASSWIDGETS_AGENT_INDEX_ROOTS.split(',').map(x=>x.trim()).filter(Boolean);
   const scanned=await fi.scan(roots); // skips Windows/Program Files/AppData etc, capped
   let entries=[...scanned].map(([p,[size,mtime]])=>({path:p,name:path.basename(p),size,mtime}));
   entries.sort((a,b)=>a.path.localeCompare(b.path));
   let json=JSON.stringify({version:1,built_at:Date.now(),entries});
   let truncated=false;
   while(Buffer.byteLength(json)>CAPS.uploadBytes&&entries.length){entries.length=Math.floor(entries.length*0.8);truncated=true;json=JSON.stringify({version:1,built_at:Date.now(),truncated:true,entries})}
   const u=new URL(uploadUrl);u.searchParams.set('name','index.json');
   const r=await fetch(u,{method:'POST',headers:{'content-type':'application/json','X-GW-Key':cmdKey},body:json,signal:AbortSignal.timeout(90000)});
   if(!r.ok)return ack(id,'failed','upload '+r.status);
   const j=await r.json().catch(()=>({}));
   if(!j.file_id)return ack(id,'failed','upload bad response');
   await ack(id,'done','indexed '+entries.length+' files from '+roots.length+' roots'+(truncated?' (truncated)':''),{file_id:String(j.file_id),files:entries.length,roots:roots.length,bytes:Buffer.byteLength(json),truncated});
  }catch(e){await ack(id,'failed','index error')}
 }

 const SSE_UNSIGNED_WINDOW_MS=10*60*1000; // unsigned SSE commands carry no signed expiry: their dedup window is bounded, never "at-most-once forever"
 const PARKED_KINDS=new Set(['run_command','web_task','media_control','ui_automation','island_control']); // effect starts at approval (execPending), not at dispatch
 async function handle(m,intake){
  if(!m||typeof m!=='object'||!m.id)return;
  const id=String(m.id);
  // ONE command-id ledger across BOTH transports (SSE + tunnel): the tunnel intake already
  // committed 'accepted' (intake.committed); the SSE leg commits HERE. Whatever the channel, an
  // id runs AT MOST ONCE: a live record blocks dispatch (incl. after a restart, where
  // crashed records reload as unknown), a terminal record replays its CACHED result
  // (idempotent re-ack, never re-executed), an unknown record is never auto-retried.
  if(!(intake&&intake.committed)){
   // transport authority window: signed exp (m.exp) AND the worker's private transport expiry
   // (expires_at - SSE envelope metadata, never a sender field) bound the effect. An unsigned
   // command without either gets a BOUNDED dedup window (not an at-most-once-forever claim);
   // a fallback resend of the same command keeps the SAME id inside that window.
   const prev=ledger.get(id); // duplicate resolution FIRST - a replay (expired or not) never rewrites a live record and never contradicts the original outcome
   if(prev){
    audit({kind:String(m.kind||'').slice(0,40),stage:'cross_transport_duplicate',id:id.slice(0,40),status:prev.status});
    if(prev.status==='done'||prev.status==='failed')ack(id,prev.status,prev.note||'cached result',prev.result||undefined); // cached terminal result - the effect NEVER re-runs; accepted/running/unknown stay silent (no ack race)
    return;
   }
   const wins=[+m.exp,+m.expires_at].filter(x=>Number.isFinite(x)&&x>0);
   const winEnd=wins.length?Math.min(...wins):Date.now()+SSE_UNSIGNED_WINDOW_MS;
   if(winEnd<=Date.now()){audit({kind:String(m.kind||'').slice(0,40),stage:'transport_expired',id:id.slice(0,40)});try{ledger.put(id,{status:'failed',note:'transport expired before effect',exp:Date.now()})}catch{}return ack(id,'failed','expired - תוקף התעבורה פג לפני הביצוע')} // authority expired BEFORE any effect - only a NEW intake gets the refusal record
   intake={...(intake||{}),exp:winEnd}; // execution-time expiry for parked cards, same as the tunnel leg
   if(!ledger.ok()){audit({kind:String(m.kind||'').slice(0,40),stage:'ledger_down',id:id.slice(0,40)});return ack(id,'failed','ledger unavailable')}
   const putR=ledger.put(id,{status:'accepted',exp:winEnd}); // the dedup tombstone lives exactly as long as the command's authority window
   if(putR==='full'){audit({kind:'server',stage:'ledger_full',id:id.slice(0,40)});return ack(id,'failed','ledger full - retry later')}
   if(putR!==true){audit({kind:'server',stage:'ledger_fail',id:id.slice(0,40)});return ack(id,'failed','ledger commit failed')}
  }
  // running gate: an immediate effect NEVER starts unless the running transition is durable.
  // transition returns false on a down store / missing record / final record - no permit, no effect.
  if(!PARKED_KINDS.has(m.kind)&&ledger.transition(id,'running')!==true){
   audit({kind:'server',stage:'running_gate_fail',id:id.slice(0,40)});
   try{ledger.put(id,{status:'failed',note:'running gate failed'})}catch{}
   return ack(id,'failed','ledger transition failed - effect blocked');
  }
  // central duplicate-id guard: a reused id (any card-parking kind, signed or not) is refused before
  // dispatch, so it can never clobber a parked approval whose original timer would run the replacement
  if((m.kind==='run_command'||m.kind==='web_task'||m.kind==='media_control'||m.kind==='ui_automation'||m.kind==='island_control')&&checkDup(m.id,m.kind,{}))return;
  const run=(async()=>{
   if(m.kind==='find_files')return findFiles(m.id,m.query,m.limit,m.folder);
   if(m.kind==='delete_file')return deleteFile(m.id,m.path);
   if(m.kind==='open_path')return openPathCmd(m.id,m.path);
   if(m.kind==='run_command')return runCommand(m.id,m.command,m,intake);
   if(m.kind==='update_app')return updateAppCmd(m.id);
   if(m.kind==='media_control')return mediaControl(m.id,m.action,intake);
   if(m.kind==='clipboard_read')return clipboardRead(m.id);
   if(m.kind==='web_task')return webTask(m.id,m,intake);
   if(m.kind==='ui_automation')return uiAutomation(m.id,m,intake);
   if(m.kind==='island_control')return islandControl(m.id,m,intake);
   if(m.kind==='screenshot')return screenshotCmd(m.id);
   if(m.kind==='index')return buildIndex(m.id);
   if(m.kind==='sys_info')return sysInfo(m.id,m.topic);
   if(m.kind==='get_file')return getFile(m.id,m.path);
   if(m.kind==='enroll_device')return enrollDeviceCmd(m,intake);
   return ack(m.id,'failed','unknown kind');
  })();
  let tOut=null;
  await Promise.race([run,new Promise(r=>{tOut=setTimeout(()=>ack(m.id,'failed','timeout').then(r,r),CAPS.cmdTimeoutMs);tOut.unref&&tOut.unref()})]);
  clearTimeout(tOut); // the watchdog must not ack after the command already answered (incl. parked approvals)
 }

 let stop=false;
 async function loop(){let backoff=1000;
  while(!stop){
   let idleT=null;const ctl=new AbortController();
   try{
    const u=new URL(cmdUrl);u.searchParams.set('key',cmdKey);u.searchParams.set('v',app.getVersion());u.searchParams.set('caps','approve,update,media,clip,web,sig,ui,shot,island'); // approve: run_command/media_control/web_task flow only to card-capable clients; update: update_app accepted (pre-authorized standing grant); media: media bridge present; clip: clipboard_read; web: background web_task; sig: Ed25519 pre-approved commands (auto-run with cancelable info card); ui: ui_automation (screen clicks, card-gated); shot: read-only screenshot
    const r=await fetch(u,{signal:ctl.signal,headers:{accept:'text/event-stream'}});
    if(!r.ok||!r.body)throw new Error('cmd stream '+r.status);
    backoff=1000;
    const poke=()=>{clearTimeout(idleT);idleT=setTimeout(()=>ctl.abort(),120000)};poke();
    const reader=r.body.getReader(),dec=new TextDecoder();let buf='';
    while(true){const{done,value}=await reader.read();if(done)break;poke();buf+=dec.decode(value,{stream:true});
     let i;while((i=buf.indexOf('\n\n'))>=0){const chunk=buf.slice(0,i);buf=buf.slice(i+2);
      const line=chunk.split('\n').find(l=>l.startsWith('data:'));if(!line)continue;
      try{const m=JSON.parse(line.slice(5).trim());if(m&&m.kind)handle(m)}catch{}}}
    throw new Error('cmd stream closed');
   }catch(e){clearTimeout(idleT);if(stop)break;await new Promise(r=>setTimeout(r,backoff));backoff=Math.min(backoff*2,15000)}
  }
 }
 const KNOWN_KINDS=new Set(['find_files','delete_file','open_path','run_command','update_app','media_control','clipboard_read','web_task','ui_automation','island_control','screenshot','index','sys_info','get_file','enroll_device']);
 // own-server leg (stage 1): the same command intake, served locally and reached through the tunnel.
 // the worker SSE loop keeps running as fallback until cutover; checkDup dedups a command that
 // somehow arrives on both channels, and every terminal state still acks over the existing leg.
 // ONE transactional ledger per tunnel command (intake -> accepted -> terminal): replay guard AND
 // task-result polling from the same durable record, so no crash window can strand a command
 // between two files. Corrupt/unwritable = tunnel intake AND /task both closed (503).
 const{createLedger,RESULT_TTL_MS,RESULT_CAP,capResult}=require('./ledger');
 const ledger=createLedger(path.join(app.getPath('userData'),'agent-tunnel-ledger.json'));
 // signed READ auth for /task and /info: the baked command key is PUBLIC (it ships in the EXE) and
 // must never gate private results. Reads carry X-GW-Read-Ts/Nonce/Sig - Ed25519 with the worker
 // key over method\npath\nquery\nts\nnonce (request-bound), ts within 60s, nonce replay-cached
 // in memory until ts+120s (read-only, so an in-memory horizon is sufficient; documented).
 const STRICT_ENVELOPES=process.env.GLASSWIDGETS_STRICT_ENVELOPES==='1'; // v2 device-bound envelopes mandatory (set before tunnel-first multi-device)
 const READ_SKEW_MS=60000,readNonces=new Map();
 function verifyReadAuth(method,pathName,query,headers){
  if(!signPub)return false;
  const ts=+headers['x-gw-read-ts'],nonce=String(headers['x-gw-read-nonce']||''),sig=String(headers['x-gw-read-sig']||'');
  const device=String(headers['x-gw-read-device']||'');
  // the signed request is bound to the TARGET DEVICE: a read captured on one device never
  // authorizes another (multi-device safe); '-' addresses a not-yet-enrolled device.
  if(devId){if(device!==devId)return false}else if(device!=='-')return false;
  if(!Number.isFinite(ts)||Math.abs(Date.now()-ts)>READ_SKEW_MS)return false;
  if(!/^[A-Za-z0-9_-]{8,64}$/.test(nonce)||!/^[0-9a-f]{128}$/.test(sig))return false;
  const now=Date.now();for(const[n,x]of readNonces)if(x<=now)readNonces.delete(n);
  const key=String(ts)+'|'+nonce;
  if(readNonces.has(key))return false; // replay
  let okV=false;
  try{okV=crypto.verify(null,Buffer.from([method,pathName,query,String(ts),nonce,device].join('\n'),'utf8'),signPub,Buffer.from(sig,'hex'))}catch{okV=false}
  if(okV)readNonces.set(key,ts+120000);
  return okV;
 }
 const srvCfg={enabled:true,port:47631,...((cfg.localServer&&typeof cfg.localServer==='object')?cfg.localServer:{})};
 if(process.env.GLASSWIDGETS_LOCAL_SERVER_ENABLED!==undefined)srvCfg.enabled=process.env.GLASSWIDGETS_LOCAL_SERVER_ENABLED==='1';
 if(process.env.GLASSWIDGETS_LOCAL_SERVER_PORT)srvCfg.port=+process.env.GLASSWIDGETS_LOCAL_SERVER_PORT||srvCfg.port;
 let srvStop=null;
 if(cmdKey&&srvCfg.enabled)resolveFolders().then(async()=>{
  if(stop||!folders.length)return; // stop() during folder resolution must not bring the listener up
  const{startLocalServer}=require('./localserver');
  const r=await startLocalServer({port:srvCfg.port,token:cmdKey,version:app.getVersion(),caps:'approve,update,media,clip,web,sig,ui,shot,island',
   getDevice:()=>devKey&&devId?{deviceId:devId,deviceSign:(t)=>deviceSign(t)}:null,
   getTask:id=>ledger.get(id),tasksOk:()=>ledger.ok(),
   getInfo:()=>({envelopeVersions:['v1','v2'],strict:!!STRICT_ENVELOPES,...(devId?{deviceId:devId,pubkey:devPubB64}:{})}),
   verifyReadAuth,log:(lvl,o)=>audit({lvl,...o}),
   onCommand:(m)=>{
    // TUNNEL INTAKE AUTHORITY: the baked cmd key is public (extractable from the downloadable EXE)
    // and proves nothing about the sender. Every tunnel command must arrive as a signed envelope
    // {id,kind,ts,exp,sig,data} - Ed25519 over id\nkind\nts\nexp\nJSON.stringify(data), signed by the
    // worker's private key (never in the EXE). Unsigned/stale/expired -> 403, audited, never handled.
    // The signature proves sender authority at INTAKE ONLY: downstream the command runs with ordinary
    // unsigned semantics - approval cards for sensitive kinds exactly as before.
    if(!KNOWN_KINDS.has(m.kind))return {accepted:false,status:400,reason:'unknown_kind'};
    const data=(m.data&&typeof m.data==='object'&&!Array.isArray(m.data))?m.data:{};
    // reserved fields: signed data must never smuggle identity/envelope fields past the intake
    for(const k of ['id','kind','ts','exp','sig','__tunnel'])if(k in data){audit({kind:'server',stage:'reserved_field',id:String(m.id||'').slice(0,40),cmd:String(m.kind||'').slice(0,40)});return {accepted:false,status:400,reason:'reserved_field'}}
    // v2 device binding: when the envelope carries a device field, the signature must cover it
    // AND it must name THIS enrolled device - the same worker-signed envelope can never be
    // collected at another device. v1 (no device field) stays accepted in stage A (single
    // device); the worker starts sending device-bound envelopes before tunnel-first multi-device.
    if(m.device!=null){
     if(!devId||String(m.device)!==String(devId)){audit({kind:'server',stage:'wrong_device',id:String(m.id||'').slice(0,40)});return {accepted:false,status:403,reason:'wrong_device'}}
     if(!validPreapproval({id:m.id,kind:m.kind,ts:m.ts,exp:m.exp,sig:m.sig},JSON.stringify(data),String(m.device))){
      audit({kind:'server',stage:'unsigned_cmd',id:String(m.id||'').slice(0,40),cmd:String(m.kind||'').slice(0,40)});
      return {accepted:false,status:403,reason:'unsigned'}}
    }else{
     // v1 (no device field) is a BOOTSTRAP/single-device path only. With strict envelopes on
     // (required before tunnel-first multi-device), an enrolled device refuses v1 outright -
     // never a strip-device fallback.
     if(STRICT_ENVELOPES&&devId){audit({kind:'server',stage:'device_required',id:String(m.id||'').slice(0,40)});return {accepted:false,status:403,reason:'device_required'}}
     if(!validPreapproval({id:m.id,kind:m.kind,ts:m.ts,exp:m.exp,sig:m.sig},JSON.stringify(data))){
      audit({kind:'server',stage:'unsigned_cmd',id:String(m.id||'').slice(0,40),cmd:String(m.kind||'').slice(0,40)});
      return {accepted:false,status:403,reason:'unsigned'}}}
    if(!ledger.ok())return {accepted:false,status:503,reason:'ledger'};
    if(ledger.has(m.id)){audit({kind:'server',stage:'duplicate',id:String(m.id).slice(0,40),cmd:String(m.kind).slice(0,40)});return {accepted:false,status:409,reason:'duplicate'}} // a replayed envelope gets a stable 409 AND its terminal record stays pollable
    // durable commit BEFORE any effect: the accepted record IS the dispatch permit. If it cannot
    // be committed, nothing runs and the sender may retry the same envelope (it was not consumed).
    const putR=ledger.put(m.id,{status:'accepted',exp:+m.exp});
    if(putR==='full'){audit({kind:'server',stage:'ledger_full',id:String(m.id).slice(0,40)});return {accepted:false,status:429,reason:'ledger_full'}} // live window saturated - retry later; NO live tombstone was evicted
    if(putR!==true){audit({kind:'server',stage:'ledger_fail',id:String(m.id).slice(0,40)});return {accepted:false,status:503,reason:'ledger'}}
    handle({...data,id:String(m.id),kind:m.kind},{tunnel:true,exp:+m.exp,committed:true}); // authenticated identity LAST; transport authority travels as an INTERNAL intake parameter, never a sender-controlled field
    return {accepted:true};
   }});
  if(stop){if(r.started)r.stop();return} // stop() raced the listen() call - tear it back down
  if(r.started){srvStop=r.stop;startTunnelLeg(r.port)}else audit({kind:'server',stage:'not_started',reason:String(r.reason||'')});
 });

 // path B: quick tunnel + authenticated discovery publish on the worker + heartbeat.
 // the worker record is a POINTER ONLY (url + timestamp); commands keep flowing over SSE until
 // the sender switches, and a stale record (no heartbeat) means the sender falls back to SSE.
 const tunnelCfg={enabled:true,...((cfg.tunnel&&typeof cfg.tunnel==='object')?cfg.tunnel:{})};
 if(process.env.GLASSWIDGETS_TUNNEL_ENABLED!==undefined)tunnelCfg.enabled=process.env.GLASSWIDGETS_TUNNEL_ENABLED==='1';
 const discoveryUrl=base.replace(/\/chat$/,'/agent/tunnel');
 // per-device credential: the keypair is GENERATED ON THIS PC (enroll_device kind, worker-signed
 // only); the private key never leaves the machine - only the public key is acked back for
 // enrollment. The baked cmd key is public and never proves device identity.
 const devDir=()=>path.join(app.getPath('userData'),'device');
 const devFile=()=>path.join(devDir(),'device.json');
 const{aclDump,currentSid,aclOwnerOnly,aclHarden}=require('./acl-win'); // the shared harden+verify module (Electron-free) - same code for agent and standalone server

 let devKey=null,devId='',devPubB64='';
 function loadDevice(){
  try{
   if(process.platform==='win32'&&(!aclOwnerOnly(devDir())||!aclOwnerOnly(devFile()))){devKey=null;devId='';devPubB64='';audit({kind:'enroll_device',stage:'acl_fail'});return} // a readable-by-others private key (dir OR file) fails closed
   const j=JSON.parse(fs.readFileSync(devFile(),'utf8'));
   const priv=crypto.createPrivateKey({key:Buffer.from(String(j.priv),'base64'),format:'der',type:'pkcs8'});
   const pub=crypto.createPublicKey(priv).export({format:'der',type:'spki'}).toString('base64');
   if(pub!==String(j.pub)){devKey=null;devId='';devPubB64='';audit({kind:'enroll_device',stage:'device_mismatch'});return} // the stored pub must DERIVE from the private key - a tampered file fails closed
   devKey=priv;devPubB64=pub;devId=crypto.createHash('sha256').update(pub).digest('hex').slice(0,16);
  }catch{devKey=null;devId='';devPubB64=''}
 }
 // harden the private DIRECTORY first (verified), then write to a UNIQUE tmp (a pre-planted tmp can
 // never smuggle ACEs in), harden it by SID, verify the effective ACL, and rename atomically.
 // Any failure = no key on disk and the enroll fails.
 function persistDevice(pubB64,privB64){
  const dir=devDir(),f=devFile(),tmp=path.join(dir,'device-'+process.pid+'-'+Date.now()+'.tmp');
  try{
   fs.mkdirSync(dir,{recursive:true});
   if(process.platform==='win32'&&!aclHarden(dir,true)){audit({kind:'enroll_device',stage:'persist_fail',err:'dir acl'});return false}
   fs.writeFileSync(tmp,JSON.stringify({pub:pubB64,priv:privB64}),{mode:0o600,flag:'wx'}); // exclusive create - a pre-existing path is never rewritten
   if(process.platform==='win32'&&!aclHarden(tmp,false)){try{fs.unlinkSync(tmp)}catch{};audit({kind:'enroll_device',stage:'persist_fail',err:'file acl'});return false}
   fs.renameSync(tmp,f);
   return true;
  }catch(e){try{fs.unlinkSync(tmp)}catch{};audit({kind:'enroll_device',stage:'persist_fail',err:String(e&&e.message||e).slice(0,120)});return false}
 }
 loadDevice();
 const deviceSign=text=>crypto.sign(null,Buffer.from(String(text),'utf8'),devKey).toString('hex');
 async function enrollDeviceCmd(m,intake){
  // worker-signed ONLY: the tunnel intake marker arrives as an INTERNAL parameter (never a sender
  // field), the flat SSE path needs a sig over the empty payload. This operation founds the device
  // identity, so it never parks a user card and never runs unsigned. STAGE 1 HAS NO ROTATION: an
  // existing identity is RETURNED, never rewritten, and any extra fields (incl. a tampered
  // 'rotate') are IGNORED - so no replay or payload tampering can ever change the keys. Explicit
  // rotation/revocation is a stage-2 design (stable identity + dedicated signed flow).
  const tun=!!(intake&&intake.tunnel===true);
  if(!tun&&!validPreapproval(m,'')){audit({kind:'enroll_device',stage:'bad_sig',id:String(m.id||'').slice(0,40)});return ack(m.id,'failed','unsigned enroll refused')}
  if(devKey&&devId){audit({kind:'enroll_device',stage:'already_enrolled',device:devId});return ack(m.id,'done','already enrolled',{deviceId:devId,pubkey:devPubB64})}
  const{publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
  const pubB64=publicKey.export({format:'der',type:'spki'}).toString('base64');
  const privB64=privateKey.export({format:'der',type:'pkcs8'}).toString('base64');
  if(!persistDevice(pubB64,privB64))return ack(m.id,'failed','device key persist failed');
  loadDevice();
  if(!devKey||devPubB64!==pubB64){audit({kind:'enroll_device',stage:'persist_fail'});return ack(m.id,'failed','device key persist failed')}
  audit({kind:'enroll_device',stage:'enrolled',device:devId});
  if(currentTunnelUrl)publishTunnel(currentTunnelUrl); // identity upgraded: republish the live pointer signed
  ack(m.id,'done','enrolled',{deviceId:devId,pubkey:pubB64}); // PUBLIC key only travels
 }
 let tunnelStop=null,heartbeat=null;
 let currentTunnelUrl='';
 async function publishTunnel(url){
  if(!devKey||!devId){audit({kind:'tunnel',stage:'no_device_key'});return} // never publish under the public baked key
  const ts=Date.now();
  try{const r=await fetch(discoveryUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({deviceId:devId,url,v:app.getVersion(),ts,sig:deviceSign(devId+'\n'+url+'\n'+ts)}),signal:AbortSignal.timeout(15000)});
   if(!r.ok)audit({kind:'tunnel',stage:'publish_fail',status:r.status});
  }catch(e){audit({kind:'tunnel',stage:'publish_error',err:String(e&&e.message||e).slice(0,120)})}
 }
 async function startTunnelLeg(port){
  if(!tunnelCfg.enabled)return;
  const{ensureCloudflared,startTunnel}=require('./tunnel');
  const exe=await ensureCloudflared(path.join(app.getPath('userData'),'bin'),{log:(stage,obj)=>audit({kind:'tunnel',stage,...obj})});
  if(stop)return; // stop() raced the download - never bring the tunnel up afterwards
  if(!exe){audit({kind:'tunnel',stage:'no_binary'});return}
  const t=startTunnel({exePath:exe,port,isStopped:()=>stop,log:(stage,obj)=>audit({kind:'tunnel',stage,...obj}),
   onDown:()=>{currentTunnelUrl='';clearInterval(heartbeat);heartbeat=null;audit({kind:'tunnel',stage:'down'});publishTunnel('')}, // best-effort clear NOW (network/D1 permitting); the 90s stale window remains the guaranteed fallback
   onUrl:(url)=>{
    currentTunnelUrl=url;
    audit({kind:'tunnel',stage:'published',url});
    publishTunnel(url);
    clearInterval(heartbeat);
    heartbeat=setInterval(()=>publishTunnel(url),45000);heartbeat.unref&&heartbeat.unref();
   }});
  tunnelStop=t.stop;
 }
 if(cmdKey)resolveFolders().then(()=>{if(folders.length)loop()});
 return {stop:()=>{stop=true;clearInterval(heartbeat);if(tunnelStop)tunnelStop();if(srvStop)srvStop()}};
}
module.exports=startAgent;
