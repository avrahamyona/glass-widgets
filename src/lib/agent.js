// Local computer-actions agent. Consumes the /glasswidgets/cmd SSE stream (receiver key) and runs
// allowlisted actions: find_files, get_file (upload via /file/upload), index, sys_info, screenshot,
// delete_file (Downloads folder only, files only), open_path, run_command, media_control, clipboard_read.
// Safety: a resolved-folder allowlist gates file reads, delete_file is pinned to the real Downloads
// folder, and every mutating/executing command lands in userData/agent-audit.log (JSON lines).
const fs=require('fs'),path=require('path'),os=require('os');
const {screen}=require('electron');
const {execFile,exec}=require('child_process');

const CAPS={maxDepth:10,maxScan:60000,contentBytes:2*1024*1024,uploadBytes:20*1024*1024,resultLen:3500,noteLen:500,cmdTimeoutMs:300000};
const SKIP_DIRS=new Set(['node_modules','.git','AppData','$Recycle.Bin','System Volume Information','.cache','.npm','.vscode','.config','Windows','Program Files','Program Files (x86)','ProgramData','$WinREAgent','Recovery','PerfLogs','.Trash']);
const TEXT_EXT=new Set(['.txt','.md','.csv','.json','.log','.xml','.html','.htm','.js','.ts','.py','.yaml','.yml','.ini','.rtf']);

function startAgent({app,rd,wr,chatKey,broadcastCard,updateApp,mediaCmd}){
 const cfg={...(rd('agent.json',{})||{})};
 const base=process.env.GLASSWIDGETS_CHAT_URL||'https://avi-music-account-staging.avi-music.workers.dev/glasswidgets/chat';
 const cmdUrl=process.env.GLASSWIDGETS_AGENT_CMD_URL||cfg.cmdUrl||base.replace(/\/chat$/,'/cmd/stream');
 const ackUrl=process.env.GLASSWIDGETS_AGENT_ACK_URL||cfg.ackUrl||base.replace(/\/chat$/,'/cmd/ack');
 const uploadUrl=process.env.GLASSWIDGETS_AGENT_UPLOAD_URL||cfg.uploadUrl||base.replace(/\/chat$/,'/file/upload');
 const CMD_KEY_BAKED='__GW_CMD_KEY__'; // CI replaces the placeholder from the GW_CMD_KEY secret; stays dormant when not injected
 const cmdKey=process.env.GLASSWIDGETS_AGENT_CMD_KEY||cfg.cmdKey||(CMD_KEY_BAKED.slice(0,5)==='__GW_'?'':CMD_KEY_BAKED);
 module.exports.cmdKey=cmdKey;

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
   const stdout=String(so||'').slice(0,3000),stderr=String(se||(e&&e.message||'')).slice(0,1000);
   audit({kind:'run_command',stage:'executed',command:cmd,ok:!e,exit:e?(e.code??null):0,stdout:stdout.slice(0,500),stderr:stderr.slice(0,300)});
   await ack(id,e?'failed':'done',e?('exit '+(e.code??'?')):'ok',{stdout,stderr,exit:e?(e.code??null):0});res();
  });
 })}

 // run_command NEVER executes on worker say-so: it parks as a pending approval, the island pops an
 // unmissable card with the exact command, and only the user's אשר tap runs it. Default deny after ~2 min.
 const pendingApprovals=new Map(); // cardId -> {cmdId,command,timer}
 const APPROVAL_TTL=+process.env.GLASSWIDGETS_APPROVAL_TTL_MS||120000;
 function runCommand(id,command){
  const cmd=String(command||'').trim();
  if(!cmd)return ack(id,'failed','missing command');
  if(cmd.length>1000)return ack(id,'failed','command too long');
  if(RUN_DENY.some(rx=>rx.test(cmd))){audit({kind:'run_command',stage:'denied',command:cmd,error:'guardrail'});return ack(id,'failed','command denied by guardrail')}
  if(pendingApprovals.size>=5)return ack(id,'failed','too many pending approvals');
  if(!broadcastCard)return ack(id,'failed','no UI for approvals');
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'run_command',stage:'expired',command:p.command});ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'run_command',command:cmd,timer});
  audit({kind:'run_command',stage:'requested',command:cmd});
  broadcastCard({id:cardId,title:'⚠️ אישור הרצת פקודה במחשב',body:'השרת מבקש להריץ:\n'+cmd+'\n\nבלי אישור - הפקודה תידחה אוטומטית בעוד כ-2 דקות.',buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
 }
 async function handleCardAction(p){
  const cardId=String(p&&p.card_id||''),pend=pendingApprovals.get(cardId);
  if(!pend)return {ok:false,reason:'expired'};
  pendingApprovals.delete(cardId);clearTimeout(pend.timer);
  if(p.button_id==='approve'){
   audit({kind:pend.kind||'run_command',stage:'approved',command:pend.command,action:pend.action});
   if(pend.kind==='media_control'){mediaApproved=true;execMedia(pend.cmdId,pend.action);return {ok:true}}
   if(pend.kind==='web_task'){execWebTask(pend.cmdId,pend.task);return {ok:true}}
   execRun(pend.cmdId,pend.command);return {ok:true}}
  audit({kind:pend.kind||'run_command',stage:'denied',command:pend.command,action:pend.action});
  ack(pend.cmdId,'failed','denied - המשתמש דחה מהאי');return {ok:true}}
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
 function mediaControl(id,action){
  const a=String(action||'').trim().toLowerCase();
  if(!MEDIA_ACTIONS.includes(a))return ack(id,'failed','bad action');
  if(mediaApproved){audit({kind:'media_control',stage:'requested',action:a,via:'session-grant'});return execMedia(id,a)}
  if(pendingApprovals.size>=5)return ack(id,'failed','too many pending approvals');
  if(!broadcastCard)return ack(id,'failed','no UI for approvals');
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'media_control',stage:'expired',action:p.action});ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'media_control',action:a,timer});
  audit({kind:'media_control',stage:'requested',action:a});
  broadcastCard({id:cardId,title:'🎵 אישור שליטה במדיה',body:'השרת מבקש שליטה בניגון במחשב (פעולה: '+a+'). אישור מתיר שליטה במדיה עד הפעלה מחדש של האפליקציה. בלי אישור - הבקשה תידחה אוטומטית בעוד כ-2 דקות.',buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
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
  if(m){const a=+m[1],b=+m[2];
   return !(a===0||a===10||a===127||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===169&&b===254)||a>=224)}
  return !(ip==='::1'||ip==='::'||/^(fe8|fe9|fea|feb|fc|fd)/i.test(ip));
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
   if(!ent)return callback({});
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
  finally{if(win&&!win.isDestroyed())win.destroy()}
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
 async function webTask(id,task){
  const url=String(task&&task.url||'').trim();
  if(!webUrlOk(url))return ack(id,'failed','url refused - https only, no private/local targets');
  if(!WEB_ALLOW_LOCAL&&!(await resolvesPublic(url,new Map()))){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'resolves private'});return ack(id,'failed','destination resolves to a private/local address - refused')}
  const rawSteps=Array.isArray(task.steps)?task.steps:[];
  if(rawSteps.length>20){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'plan too long',steps:rawSteps.length});return ack(id,'failed','plan too long to review safely (max 20 steps) - rejected')}
  const plan=webTaskPlan(url,rawSteps);
  if(plan.length>1400){audit({kind:'web_task',stage:'failed',url:url.slice(0,200),error:'plan too long',chars:plan.length});return ack(id,'failed','plan too long to review safely ('+plan.length+' chars) - rejected')}
  if(pendingApprovals.size>=5)return ack(id,'failed','too many pending approvals');
  if(!broadcastCard)return ack(id,'failed','no UI for approvals');
  const steps=rawSteps;
  const cardId='local-approve-'+String(id).replace(/[^\w-]/g,'').slice(0,60);
  const timer=setTimeout(()=>{const p=pendingApprovals.get(cardId);if(!p)return;pendingApprovals.delete(cardId);
   audit({kind:'web_task',stage:'expired',url:p.task&&p.task.url});ack(p.cmdId,'failed','expired - לא אושר תוך כ-2 דקות')},APPROVAL_TTL);
  timer.unref&&timer.unref();
  pendingApprovals.set(cardId,{cmdId:id,kind:'web_task',task:{url,steps},timer});
  audit({kind:'web_task',stage:'requested',url:url.slice(0,200),steps:steps.length});
  const label=String(task.label||'').slice(0,200);
  broadcastCard({id:cardId,title:'🌐 אישור משימת אתר ברקע',body:'השרת מבקש לבצע משימת דפדפן נסתרת במחשב:'+(label?'\n'+label:'')+'\n'+url.slice(0,200)+(plan?'\n\nהצעדים:\n'+plan:'')+'\n\nהמשימה רצה ברקע בלבד ולא נוגעת במסך או בעכבר. בלי אישור - תידחה אוטומטית בעוד כ-2 דקות.',buttons:[{id:'approve',label:'אשר',style:'primary'},{id:'deny',label:'דחה',style:'danger'}]});
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

 async function ack(id,status,note,result){
  const body={key:cmdKey,id:String(id||''),status,note:String(note||'').slice(0,CAPS.noteLen)};
  if(result!==undefined){let s=JSON.stringify(result);if(s.length>CAPS.resultLen&&Array.isArray(result.matches)){const m=[...result.matches];while(m.length&&s.length>CAPS.resultLen){m.pop();s=JSON.stringify({matches:m})}result={matches:m}}body.result=result}
  try{await fetch(ackUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)})}catch{}
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

 async function handle(m){
  if(!m||typeof m!=='object'||!m.id)return;
  const run=(async()=>{
   if(m.kind==='find_files')return findFiles(m.id,m.query,m.limit,m.folder);
   if(m.kind==='delete_file')return deleteFile(m.id,m.path);
   if(m.kind==='open_path')return openPathCmd(m.id,m.path);
   if(m.kind==='run_command')return runCommand(m.id,m.command);
   if(m.kind==='update_app')return updateAppCmd(m.id);
   if(m.kind==='media_control')return mediaControl(m.id,m.action);
   if(m.kind==='clipboard_read')return clipboardRead(m.id);
   if(m.kind==='web_task')return webTask(m.id,m);
   if(m.kind==='index')return buildIndex(m.id);
   if(m.kind==='sys_info')return sysInfo(m.id,m.topic);
   if(m.kind==='get_file')return getFile(m.id,m.path);
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
    const u=new URL(cmdUrl);u.searchParams.set('key',cmdKey);u.searchParams.set('v',app.getVersion());u.searchParams.set('caps','approve,update,media,clip,web'); // approve: run_command/media_control/web_task flow only to card-capable clients; update: update_app accepted (pre-authorized standing grant); media: media bridge present; clip: clipboard_read; web: background web_task
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
 if(cmdKey)resolveFolders().then(()=>{if(folders.length)loop()});
 return {stop:()=>{stop=true}};
}
module.exports=startAgent;
