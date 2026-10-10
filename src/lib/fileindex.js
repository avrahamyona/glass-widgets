// Persistent whole-PC file index + semantic search.
// One JSON index (path+size+mtime) built by background scans: a full scan when missing/stale and
// every night at 03:00, incremental home refreshes every 30 min. Search is path-wide (every parent
// folder + filename + extension), Hebrew<->English with synonyms and light morphology, so
// "מצגת שוק של מדריכי קורס 60" finds אברהם/מדא/מצגות מדריכים קורס 60/Shock.pptx.
const fs=require('fs'),path=require('path'),os=require('os');
const SKIP=new Set(['node_modules','.git','AppData','$Recycle.Bin','System Volume Information','.cache','.npm','.vscode','.config','Windows','Program Files','Program Files (x86)','ProgramData','$WinREAgent','Recovery','PerfLogs','.Trash']);
const STOP=new Set(['של','את','עם','על','אל','מה','זה','לי','שלי','the','of','for','a','an','to','my','me','and','in','on']);
const SYN={
 'מצגת':['presentation','ppt','pptx'],'הצגה':['presentation','ppt'],'מסמך':['document','doc','docx'],'תמונה':['image','photo','picture','img'],'שיר':['song','mp3'],'סרטון':['video','mp4','movie'],'וידאו':['video','mp4'],'חשבונית':['invoice'],'קורות':['cv','resume'],'אקסל':['excel','xlsx'],'טבלה':['table','xlsx','csv'],'סיכום':['summary'],'מוזיקה':['music','audio'],'ספר':['book','epub'],'עבודה':['work','assignment'],'מבחן':['exam','test'],'בדיקה':['test'],
 'נשימה':['respiration','breathing','airway','breath'],'שוק':['shock'],'החייאה':['cpr','resuscitation'],'פרמדיק':['paramedic','paramedics','ems'],'עזרה':['aid','help'],'דם':['blood','bleeding','hemorrhage'],'טראומה':['trauma'],'פציעה':['injury','trauma'],'לב':['heart','cardiac'],'מדא':['mda','ems'],'מדריך':['instructor','guide'],'קורס':['course','class'],'שיעור':['lesson','class'],'תרגיל':['exercise','drill'],'הכרה':['consciousness'],'כאב':['pain'],'טיפול':['treatment','care','therapy'],'חמצן':['oxygen'],'אמבולנס':['ambulance'],'תרופות':['medication','medicine','drugs'],'אלרגיה':['allergy'],'סוכרת':['diabetes'],'בטיחות':['safety'],'ילדים':['children','pediatric','kids'],'הריון':['pregnancy'],'כוויה':['burn'],'כוויות':['burns'],'שבר':['fracture'],'שברים':['fractures'],'התחבושת':['bandage'],'חבישה':['bandage','bandaging'],'הערכה':['assessment','evaluation'],'נהלים':['procedures','protocol'],'פרוטוקול':['protocol']};
const SYN_REV={};for(const [he,alts] of Object.entries(SYN))for(const a of alts){(SYN_REV[a]=SYN_REV[a]||new Set()).add(he);for(const x of alts)if(x!==a)SYN_REV[a].add(x)}
const HEB=/[\u0590-\u05FF]/;
const FINALS={'\u05da':'\u05db','\u05dd':'\u05de','\u05df':'\u05e0','\u05e3':'\u05e4','\u05e5':'\u05e6'};
const norm=s=>String(s||'').toLowerCase().replace(/[\u05da\u05dd\u05df\u05e3\u05e5]/g,m=>FINALS[m]); // final letters match their regular forms
function variants(t){const v=new Set([t]);
 if(HEB.test(t)){
  for(const p of ['וה','שה','מה','בה','לה','כה','ו','ה','ב','ל','מ','ש','כ'])if(t.startsWith(p)&&t.length>p.length+2)v.add(t.slice(p.length));
  const base=[...v];for(const b of base){for(const suf of ['יים','ים','יות','ות','ית','י','ה','ת'])if(b.endsWith(suf)&&b.length>suf.length+2)v.add(b.slice(0,-suf.length))}
  const stems=[...v];for(const st of stems)if(HEB.test(st)&&st.length>=3){v.add(st+'ים');v.add(st+'ות');v.add(st+'י')}
 }else{
  if(t.length>3&&t.endsWith('s'))v.add(t.slice(0,-1));
  if(t.length>4&&t.endsWith('es'))v.add(t.slice(0,-2));
  v.add(t+'s')}
 return [...v]}
function groups(query){return norm(query).split(/\s+/).filter(t=>t.length>=2&&!STOP.has(t)).slice(0,6).map(t=>{
 const g=new Set([t]);for(const a of variants(t))g.add(a);
 for(const [he,alts] of Object.entries(SYN))if(t.includes(he)||alts.some(a=>t.includes(a))){g.add(he);for(const a of alts)g.add(a);for(const hv of variants(he))g.add(hv)}
 if(SYN_REV[t])for(const a of SYN_REV[t]){g.add(a);if(HEB.test(a))for(const hv of variants(a))g.add(hv)}
 return [...g].map(norm)})}
const escRe=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
function scoreEntry(low,gs){
 const name=path.basename(low),dir=path.dirname(low);
 let s=0;
 for(const g of gs){
  let best=0;
  for(const a of g){
   if(name.includes(a))best=Math.max(best,new RegExp('(^|[\\s_\\-.])'+escRe(a)+'([\\s_\\-.]|$)').test(name)?60:40);
   else if(dir.includes(a))best=Math.max(best,new RegExp('(^|[\\\\/\\s_\\-.])'+escRe(a)+'([\\s_\\-.]|$)').test(dir)?25:15);
   if(best===60)break}
  if(!best)return -1;
  s+=best}
 return s}
const S={dir:null,file:null,entries:new Map(),state:'empty',builtAt:0,scanning:false,started:false,timers:[]};
function init(o){S.dir=o.dir;S.file=path.join(o.dir,'file-index.json');
 try{const j=JSON.parse(fs.readFileSync(S.file,'utf8'));if(j&&Array.isArray(j.entries)){for(const e of j.entries)S.entries.set(e[0],[e[1],e[2]]);S.builtAt=j.built_at||0;if(S.entries.size)S.state='ready'}}catch{}}
async function save(){try{const tmp=S.file+'.tmp';fs.writeFileSync(tmp,JSON.stringify({version:1,built_at:S.builtAt,entries:[...S.entries].map(([p,[sz,mo]])=>[p,sz,mo])}));fs.renameSync(tmp,S.file)}catch{}}
function localRoots(){const env=process.env.GLASSWIDGETS_INDEX_ROOTS;if(env)return env.split(/[,;]/).map(x=>x.trim()).filter(Boolean);return [os.homedir()]} // env list is comma/semicolon separated - ':' is a drive-letter char on Windows, not a separator
function allRoots(){const r=localRoots();
 if(process.platform==='win32'&&!process.env.GLASSWIDGETS_INDEX_ROOTS){for(const c of 'CDEFGHIJKLMNOPQRSTUVWXYZ'){const d=c+':\\';try{if(fs.existsSync(d)&&!r.includes(d))r.push(d)}catch{}}}
 return r}
async function scan(roots){
 const map=new Map(),state={scanned:0,maxScan:300000,deadline:Date.now()+10*60*1000};
 async function walk(dir,depth){
  if(depth>12||state.scanned>=state.maxScan||Date.now()>state.deadline)return;
  let ents;try{ents=await fs.promises.readdir(dir,{withFileTypes:true})}catch{return}
  const sub=[];
  for(const e of ents){
   if(state.scanned>=state.maxScan||Date.now()>state.deadline)break;
   const full=path.join(dir,e.name);
   if(e.isDirectory()){if(!SKIP.has(e.name)&&!e.name.startsWith('.'))sub.push(full);continue}
   if(!e.isFile())continue;
   state.scanned++;
   try{const st=await fs.promises.stat(full);map.set(full,[st.size,Math.round(st.mtimeMs)])}catch{}}
  await Promise.all(sub.map(d=>walk(d,depth+1)))}
 await Promise.all(roots.map(r=>walk(r,0)));
 return map}
let passLock=false;
async function pass(roots){
 if(passLock)return;passLock=true;S.scanning=true;
 try{
  const fresh=await scan(roots);
  for(const p of [...S.entries.keys()])if(roots.some(r=>p.startsWith(r)))S.entries.delete(p);
  for(const [p,v] of fresh)S.entries.set(p,v);
  S.builtAt=Date.now();S.state='ready';await save();
 }catch{}finally{passLock=false;S.scanning=false}}
function startAuto(log){
 if(S.started||!S.dir)return;S.started=true;
 const say=m=>{try{log&&log(m)}catch{}};
 if(!S.builtAt||Date.now()-S.builtAt>24*3600*1000)pass(allRoots()).then(()=>say('fileindex '+S.entries.size+' entries'));
 const t30=setInterval(()=>{pass(localRoots()).then(()=>say('fileindex refresh '+S.entries.size))},30*60*1000);t30.unref&&t30.unref();
 const next=new Date();next.setHours(3,0,0,0);if(next.getTime()<=Date.now())next.setDate(next.getDate()+1);
 const tNight=setTimeout(()=>{pass(allRoots());const t24=setInterval(()=>pass(allRoots()),24*3600*1000);t24.unref&&t24.unref();S.timers.push(t24)},next.getTime()-Date.now());tNight.unref&&tNight.unref();
 S.timers.push(t30,tNight)}
function stop(){for(const t of S.timers){clearInterval(t);clearTimeout(t)}S.timers=[];S.started=false}
function ready(){return S.state==='ready'&&S.entries.size>0}
function search(query,limit=8){
 const gs=groups(query);if(!gs.length||!S.entries.size)return[];
 const survivors=[];
 for(const [p,[size,modified]] of S.entries){
  const low=norm(p);
  let ok=true;
  for(const g of gs){if(!g.some(a=>low.includes(a))){ok=false;break}}
  if(!ok)continue;
  const sc=scoreEntry(low,gs);
  if(sc>0)survivors.push({path:p,name:path.basename(p),size,modified,score:sc})}
 survivors.sort((a,b)=>b.score-a.score||b.modified-a.modified);
 return survivors.slice(0,limit)}
function stats(){return {state:S.state,entries:S.entries.size,built_at:S.builtAt,scanning:S.scanning}}
module.exports={init,startAuto,stop,ready,search,stats,pass,scan,localRoots,allRoots,groups};
