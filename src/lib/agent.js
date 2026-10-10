// Local computer-actions agent (read-only v1). Consumes the /glasswidgets/cmd SSE stream
// (receiver key) and runs allowlisted actions: find_files and get_file (upload via /file/upload).
// Safety: a resolved-folder allowlist gates every file touch; nothing executes; failures ack cleanly.
const fs=require('fs'),path=require('path'),os=require('os');
const {screen}=require('electron');
const {execFile}=require('child_process');

const CAPS={maxDepth:8,maxScan:2000,contentBytes:2*1024*1024,uploadBytes:20*1024*1024,resultLen:3500,noteLen:500,cmdTimeoutMs:120000};
const SKIP_DIRS=new Set(['node_modules','.git','AppData','$Recycle.Bin','System Volume Information','.cache','.npm','.vscode','.config']);
const TEXT_EXT=new Set(['.txt','.md','.csv','.json','.log','.xml','.html','.htm','.js','.ts','.py','.yaml','.yml','.ini','.rtf']);

function startAgent({app,rd,wr,chatKey}){
 const cfg={...(rd('agent.json',{})||{})};
 const base=process.env.GLASSWIDGETS_CHAT_URL||'https://avi-music-account-staging.avi-music.workers.dev/glasswidgets/chat';
 const cmdUrl=process.env.GLASSWIDGETS_AGENT_CMD_URL||cfg.cmdUrl||base.replace(/\/chat$/,'/cmd/stream');
 const ackUrl=process.env.GLASSWIDGETS_AGENT_ACK_URL||cfg.ackUrl||base.replace(/\/chat$/,'/cmd/ack');
 const uploadUrl=process.env.GLASSWIDGETS_AGENT_UPLOAD_URL||cfg.uploadUrl||base.replace(/\/chat$/,'/file/upload');
 const CMD_KEY_BAKED='__GW_CMD_KEY__'; // CI replaces the placeholder from the GW_CMD_KEY secret; stays dormant when not injected
 const cmdKey=process.env.GLASSWIDGETS_AGENT_CMD_KEY||cfg.cmdKey||(CMD_KEY_BAKED.slice(0,5)==='__GW_'?'':CMD_KEY_BAKED);

 let folders=[];
 async function resolveFolders(){
  const list=process.env.GLASSWIDGETS_AGENT_FOLDERS?process.env.GLASSWIDGETS_AGENT_FOLDERS.split(',').map(s=>s.trim()).filter(Boolean)
   :(Array.isArray(cfg.folders)&&cfg.folders.length?cfg.folders:['Documents','Desktop','Downloads'].map(d=>path.join(os.homedir(),d)));
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

 async function ack(id,status,note,result){
  const body={key:cmdKey,id:String(id||''),status,note:String(note||'').slice(0,CAPS.noteLen)};
  if(result!==undefined){let s=JSON.stringify(result);if(s.length>CAPS.resultLen&&Array.isArray(result.matches)){const m=[...result.matches];while(m.length&&s.length>CAPS.resultLen){m.pop();s=JSON.stringify({matches:m})}result={matches:m}}body.result=result}
  try{await fetch(ackUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)})}catch{}
 }

 async function walk(dir,depth,terms,hits,state){
  if(depth>CAPS.maxDepth||state.scanned>=CAPS.maxScan)return;
  let ents;try{ents=await fs.promises.readdir(dir,{withFileTypes:true})}catch{return}
  for(const e of ents){
   if(state.scanned>=CAPS.maxScan)return;
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
  let roots=folders,scope='';
  if(folder){
   let rf=null;try{rf=await fs.promises.realpath(String(folder))}catch{}
   if(!rf)return ack(id,'failed','folder not found');
   try{if(!(await fs.promises.stat(rf)).isDirectory())return ack(id,'failed','not a folder')}catch{return ack(id,'failed','not a folder')}
   roots=[rf];scope=' in '+rf;
  }
  const hits=[],state={scanned:0,contentLeft:400};
  for(const f of roots)await walk(f,0,terms,hits,state);
  hits.sort((a,b)=>b.modified-a.modified);
  const lim=Math.min(Math.max(1,+limit||10),20);
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

 async function handle(m){
  if(!m||typeof m!=='object'||!m.id)return;
  const run=(async()=>{
   if(m.kind==='find_files')return findFiles(m.id,m.query,m.limit,m.folder);
   if(m.kind==='sys_info')return sysInfo(m.id,m.topic);
   if(m.kind==='get_file')return getFile(m.id,m.path);
   return ack(m.id,'failed','unknown kind');
  })();
  await Promise.race([run,new Promise(r=>setTimeout(()=>ack(m.id,'failed','timeout').then(r,r),CAPS.cmdTimeoutMs))]);
 }

 let stop=false;
 async function loop(){let backoff=1000;
  while(!stop){
   let idleT=null;const ctl=new AbortController();
   try{
    const u=new URL(cmdUrl);u.searchParams.set('key',cmdKey);u.searchParams.set('v',app.getVersion());
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
