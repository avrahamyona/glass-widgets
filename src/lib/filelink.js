// "שלח לי קישור ל..." / "send me a link to ..." - a local chat command handled on the PC:
// find the file anywhere on the machine, upload it through the existing worker file route, reply in-chat with the link.
// No new secrets: upload uses the same receiver key as the agent module (CI-injected / env / agent.json).
const fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto');
let deps=null;const pending=new Map(); // card_id -> matches
const SKIP=new Set(['node_modules','.git','AppData','$Recycle.Bin','System Volume Information','.cache','.npm','.vscode','.config','Windows','Program Files','Program Files (x86)','ProgramData','$WinREAgent','Recovery','PerfLogs','.Trash']);
const SYN={'מצגת':['presentation','ppt','pptx'],'הצגה':['presentation','ppt'],'מסמך':['document','doc','docx'],'תמונה':['image','photo','picture','img'],'שיר':['song','mp3'],'סרטון':['video','mp4','movie'],'וידאו':['video','mp4'],'חשבונית':['invoice'],'קורות':['cv','resume'],'אקסל':['excel','xlsx'],'טבלה':['table','xlsx','csv'],'סיכום':['summary'],'מוזיקה':['music','audio'],'ספר':['book','epub'],'עבודה':['work','assignment'],'מבחן':['exam','test'],'בדיקה':['test']};
const SYN_REV={};for(const [he,alts] of Object.entries(SYN))for(const a of alts){(SYN_REV[a]=SYN_REV[a]||new Set()).add(he);SYN_REV[a].add(...alts.filter(x=>x!==a))}
const PREFIXES=['שלח לי קישור ל','תשלח לי קישור ל','שלח לי לינק ל','שלח קישור ל','תשלח קישור ל','תביא לי קישור ל','קישור ל','לינק ל','send me a link to','send me the link to','send a link to','send link to','get me a link to','give me a link to','link to','link for'];
function parseLinkQuery(text){const t=String(text||'').trim(),low=t.toLowerCase();
 for(const p of PREFIXES)if(low.startsWith(p)){const q=t.slice(p.length).trim().replace(/^["'«»]|["'«»]$/g,'').trim();if(q.length>=2&&q.length<=120)return q}
 return null}
function groups(query){return query.toLowerCase().split(/\s+/).filter(t=>t.length>=2).slice(0,6).map(t=>{const g=new Set([t]);for(const [he,alts] of Object.entries(SYN))if(t.includes(he)||alts.some(a=>t.includes(a))){g.add(he);alts.forEach(a=>g.add(a))}if(SYN_REV[t])SYN_REV[t].forEach(a=>g.add(a));return [...g]})}
function score(name,query,groupsArr){const low=name.toLowerCase(),q=query.toLowerCase();
 if(low===q||low===q+path.extname(low))return 100;
 let s=0;for(const g of groupsArr){if(!g.some(a=>low.includes(a)))return -1; // every term group must hit
  if(g.some(a=>low.startsWith(a)))s=Math.max(s,60);else if(g.some(a=>new RegExp('(^|[\\s_\\-.])'+a.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'([\\s_\\-.]|$)').test(low)))s=Math.max(s,30);else s=Math.max(s,10)}
 return s}
async function walk(dir,depth,gs,q,hits,state){
 if(depth>10||state.scanned>=state.maxScan||Date.now()>state.deadline)return;
 let ents;try{ents=await fs.promises.readdir(dir,{withFileTypes:true})}catch{return}
 for(const e of ents){
  if(state.scanned>=state.maxScan||Date.now()>state.deadline)return;
  const full=path.join(dir,e.name);
  if(e.isDirectory()){if(!SKIP.has(e.name)&&!e.name.startsWith('.'))await walk(full,depth+1,gs,q,hits,state);continue}
  if(!e.isFile())continue;
  state.scanned++;
  const sc=score(e.name,q,gs);if(sc<0)continue;
  try{const st=await fs.promises.stat(full);hits.push({path:full,name:e.name,size:st.size,modified:Math.round(st.mtimeMs),score:sc})}catch{}}
}
function roots(){const r=[os.homedir()];
 if(process.platform==='win32'){for(const c of 'CDEFGHIJKLMNOPQRSTUVWXYZ'){const d=c+':\\';try{if(fs.existsSync(d)&&d.toUpperCase()!==(process.env.SystemDrive||'C:').toUpperCase()+'\\')r.push(d)}catch{}}
  const sd=(process.env.SystemDrive||'C:')+'\\';if(!r.includes(sd))r.push(sd)}
 return r}
async function searchFiles(query){const gs=groups(query);if(!gs.length)return[];
 const hits=[],state={scanned:0,maxScan:60000,deadline:Date.now()+12000};
 for(const r of roots())await walk(r,0,gs,query,hits,state);
 hits.sort((a,b)=>b.score-a.score||b.modified-a.modified);
 return hits.slice(0,8)}
const MIME={'.pdf':'application/pdf','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.txt':'text/plain','.md':'text/markdown','.csv':'text/csv','.json':'application/json','.zip':'application/zip','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','.pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation','.mp3':'audio/mpeg','.mp4':'video/mp4'};
function cmdKey(){const k=process.env.GLASSWIDGETS_AGENT_CMD_KEY||require('./agent').cmdKey;return k&&String(k).slice(0,5)!=='__GW_'?k:''}
function fmtSize(n){return n>1048576?(n/1048576).toFixed(1)+'MB':Math.max(1,Math.round(n/1024))+'KB'}
async function sendFileLink(m){
 const reply=t=>deps.broadcastChat({id:'local-'+crypto.randomUUID(),text:t,at:Date.now(),received_at:0,in_reply_to:''});
 if(m.size>20*1024*1024)return reply('הקובץ "'+m.name+'" גדול מדי לשליחה ('+fmtSize(m.size)+' - המקסימום 20MB)');
 const key=cmdKey();if(!key)return reply('מצאתי את "'+m.name+'" אבל שליחת קבצים עוד לא מחוברת - ממתין למפתח הפקודות מהשרת');
 try{
  const up=deps.chatUrl.replace(/\/chat$/,'/file/upload')+'?name='+encodeURIComponent(m.name);
  const bytes=await fs.promises.readFile(m.path);
  const r=await fetch(up,{method:'POST',headers:{'x-gw-key':key,'content-type':MIME[path.extname(m.name).toLowerCase()]||'application/octet-stream'},body:bytes,signal:AbortSignal.timeout(60000)});
  const j=await r.json().catch(()=>({}));
  if(r.ok&&j.ok&&j.file_id){const link=(process.env.GLASSWIDGETS_FILE_LINK_URL||deps.chatUrl.replace(/\/chat$/,'/file/d/'))+j.file_id;
   return reply('הנה הקישור ל-'+m.name+' ('+fmtSize(m.size)+'):\n'+link+'\nהקישור תקף לשעה')}
  if(r.status===403)return reply('שגיאת מפתח מול השרת - שליחת קבצים לא מאושרת עדיין');
  if(r.status===413)return reply('הקובץ גדול מדי לשליחה (20MB מקסימום)');
  return reply('ההעלאה נכשלה ('+r.status+') - נסה שוב בעוד רגע')}
 catch{return reply('אין חיבור כרגע - ההעלאה לא הצליחה')}}
async function handle(query){
 const reply=t=>deps.broadcastChat({id:'local-'+crypto.randomUUID(),text:t,at:Date.now(),received_at:0,in_reply_to:''});
 reply('מחפש את "'+query+'"…');
 const matches=await searchFiles(query);
 if(!matches.length)return reply('לא מצאתי קובץ עם השם "'+query+'"');
 if(matches.length===1||matches[0].score>=60&&matches[0].score-matches[1].score>=40)return sendFileLink(matches[0]);
 const top=matches.slice(0,5),id='local-link-'+crypto.randomUUID();
 pending.set(id,top);setTimeout(()=>pending.delete(id),30*60*1000);
 deps.broadcastCard({id,title:'נמצאו כמה קבצים - איזה מהם?',body:top.map((m,i)=>(i+1)+'. '+m.name+' · '+fmtSize(m.size)+' · '+path.dirname(m.path)).join('\n').slice(0,900),
  buttons:top.map((m,i)=>({id:String(i),label:(i+1)+'. '+m.name.slice(0,30),style:i?'l':'p'})),at:Date.now()})}
async function handleCardAction(p){
 const matches=pending.get(String(p.card_id));if(!matches)return {ok:false,error:'expired'};
 const m=matches[+p.button_id];if(!m)return {ok:false};
 sendFileLink(m); // reply arrives as a follow-up chat row
 return {ok:true}}
module.exports={init:d=>{deps=d},parseLinkQuery,handle,handleCardAction,searchFiles};
