const {app,BrowserWindow,Menu,Tray,nativeImage,ipcMain,clipboard,safeStorage}=require('electron');
const {spawn}=require('child_process'),http=require('http'),crypto=require('crypto');
const {parseAirPods}=require('./lib/airpods'),caldav=require('./lib/caldav'),net=require('./lib/net');
const path=require('path'),fs=require('fs'),os=require('os');
const TZ='Asia/Jerusalem';
const CITY={name:'פתח תקווה',lat:32.0840,lon:34.8878,tz:TZ};
// 170px card + 14px margin each side for the shadow
const WIDGETS={
  clock:{label:'שעון',w:200,h:200,x:60,y:60},
  weather:{label:'מזג אוויר',w:200,h:200,x:280,y:60},
  notes:{label:'פתקים',w:200,h:200,x:500,y:60},
  sysmon:{label:'ניטור מערכת',w:400,h:200,x:60,y:280},
  clipboard:{label:'היסטוריית העתקות',w:260,h:400,x:480,y:280},
  calendar:{label:'לוח שנה',w:200,h:200,x:780,y:60},
  units:{label:'ממיר יחידות',w:260,h:200,x:780,y:280},
  network:{label:'רשת',w:200,h:200,x:1060,y:60},
  battery:{label:'סוללה',w:400,h:200,x:60,y:500},
  nowplaying:{label:'מנגן עכשיו',w:400,h:200,x:480,y:500}
};
const U=()=>app.getPath('userData');
const rd=(f,d)=>{try{return JSON.parse(fs.readFileSync(path.join(U(),f)))}catch{return d}};
const wr=(f,v)=>fs.writeFileSync(path.join(U(),f),JSON.stringify(v));
const wins={};
function open(id){
  const d=WIDGETS[id],s=(rd('layout.json',{}))[id]||{};
  const w=new BrowserWindow({width:d.w,height:d.h,x:s.x??d.x,y:s.y??d.y,frame:false,transparent:true,hasShadow:false,
    resizable:false,skipTaskbar:true,show:false,
    webPreferences:{preload:path.join(__dirname,'preload.js'),contextIsolation:true,nodeIntegration:false}});
  w.loadFile(path.join(__dirname,'widgets',id,'index.html'),{query:wq(id)});
  w.once('ready-to-show',()=>{w.show();if(getSet().onTop)w.setAlwaysOnTop(true,'screen-saver')});
  w.on('moved',()=>{const c=rd('layout.json',{});const [x,y]=w.getPosition();c[id]={x,y};wr('layout.json',c)});
  w.on('closed',()=>{delete wins[id]});
  wins[id]=w;
  const en=rd('enabled.json',{});en[id]=true;wr('enabled.json',en);
}
function toggle(id){
  if(wins[id]){const en=rd('enabled.json',{});en[id]=false;wr('enabled.json',en);wins[id].close()}else open(id);
}
// CPU usage from os.cpus deltas
let prev=os.cpus().map(c=>({...c.times}));let cpuPct=0;
setInterval(()=>{const cur=os.cpus().map(c=>({...c.times}));let idle=0,tot=0;
  cur.forEach((c,i)=>{const p=prev[i];const t=Object.keys(c).reduce((a,k)=>a+c[k]-p[k],0);idle+=c.idle-p.idle;tot+=t});
  cpuPct=tot?Math.round(100*(1-idle/tot)):0;prev=cur},1000);
ipcMain.handle('sys:stats',()=>{
  const total=os.totalmem(),free=os.freemem();let disk=null;
  try{const s=fs.statfsSync(process.platform==='win32'?(process.env.SystemDrive||'C:')+'\\':'/');
    disk={total:s.blocks*s.bsize,free:s.bavail*s.bsize}}catch{}
  return {cpu:cpuPct,mem:{total,used:total-free},disk,uptime:os.uptime()};
});
ipcMain.handle('notes:get',()=>rd('notes.json',{text:''}).text);
ipcMain.handle('notes:save',(_,t)=>{wr('notes.json',{text:String(t).slice(0,20000)})});
let clips=[];let lastClip='';
function pollClip(){const t=clipboard.readText();
  if(t&&t!==lastClip){lastClip=t;clips=[t,...clips.filter(x=>x!==t)].slice(0,30);wr('clips.json',clips);
    Object.values(wins).forEach(w=>w.webContents.send('clip:update',clips))}}
ipcMain.handle('clip:list',()=>clips);
ipcMain.handle('clip:copy',(_,t)=>{lastClip=t;clipboard.writeText(t)});
ipcMain.handle('clip:clear',()=>{clips=[];wr('clips.json',clips);Object.values(wins).forEach(w=>w.webContents.send('clip:update',clips))});
ipcMain.handle('cfg:get',()=>{const c=getSet().city;return c?{...CITY,...c}:CITY});


// ---- settings (theme, per-widget style, general)
const DEF={theme:'auto',onTop:false,styles:{clock:'analog',sysmon:'rings',notes:'yellow'},city:null};
const getSet=()=>{const s=rd('settings.json',{});return {...DEF,...s,styles:{...DEF.styles,...(s.styles||{})}}};
function wq(id){const s=getSet(),q={};if(s.theme!=='auto')q.theme=s.theme;if(s.styles[id])q.style=s.styles[id];return q}
function reload(id){const w=wins[id];if(w)w.loadFile(path.join(__dirname,'widgets',id,'index.html'),{query:wq(id)})}
let setWin=null;
function openSettings(){
  if(setWin){setWin.show();setWin.focus();return}
  setWin=new BrowserWindow({width:520,height:720,minWidth:460,minHeight:520,title:'GlassWidgets',backgroundColor:'#f2f2f7',autoHideMenuBar:true,
    webPreferences:{preload:path.join(__dirname,'preload.js'),contextIsolation:true,nodeIntegration:false}});
  setWin.setMenu(null);
  setWin.loadFile(path.join(__dirname,'settings','index.html'));
  setWin.on('closed',()=>{setWin=null}); // closing never touches the widgets
}
ipcMain.handle('set:get',()=>{const en=rd('enabled.json',{});return {settings:getSet(),
  widgets:Object.keys(WIDGETS).map(id=>({id,label:WIDGETS[id].label,on:!!wins[id]})),
  autostart:app.getLoginItemSettings().openAtLogin,version:app.getVersion()}});
ipcMain.handle('set:toggle',(_,id,on)=>{if(!WIDGETS[id])return;if(on&&!wins[id])open(id);else if(!on&&wins[id])toggle(id);return !!wins[id]});
ipcMain.handle('set:save',(_,patch)=>{const cur=getSet();const next={...cur,...patch,styles:{...cur.styles,...(patch.styles||{})}};wr('settings.json',next);
  const themeChanged=next.theme!==cur.theme;
  for(const id of Object.keys(wins)){if(themeChanged||(patch.styles&&patch.styles[id]!==undefined&&patch.styles[id]!==cur.styles[id])||(id==='weather'&&patch.city!==undefined))reload(id)}
  if(patch.onTop!==undefined)Object.values(wins).forEach(w=>w.setAlwaysOnTop(!!next.onTop,'screen-saver'));
  if(patch.autostart!==undefined)app.setLoginItemSettings({openAtLogin:!!patch.autostart});
  return next});
// ---- network
ipcMain.handle('net:get',()=>net.get());
// ---- calendar (iCloud CalDAV; app-specific password kept encrypted with the OS)
const credFile='cal.bin';
function loadCreds(){try{const b=fs.readFileSync(path.join(U(),credFile));return JSON.parse(safeStorage.isEncryptionAvailable()?safeStorage.decryptString(b):b.toString())}catch{return null}}
ipcMain.handle('cal:status',()=>({connected:!!loadCreds()}));
ipcMain.handle('cal:connect',async(_,user,pw)=>{
  try{await caldav.fetchEvents(user,pw,new Date(),new Date(Date.now()+864e5));
    const j=JSON.stringify({user,pw});fs.writeFileSync(path.join(U(),credFile),safeStorage.isEncryptionAvailable()?safeStorage.encryptString(j):Buffer.from(j));return {ok:true}}
  catch(e){return {ok:false,error:e.message==='AUTH'?'Apple ID או סיסמה ייעודית שגויים':e.message}}});
ipcMain.handle('cal:disconnect',()=>{try{fs.unlinkSync(path.join(U(),credFile))}catch{}});
ipcMain.handle('cal:events',async()=>{const c=loadCreds();if(!c)return {connected:false,events:[]};
  const cache=rd('calcache.json',{events:[]});
  const from=new Date();from.setHours(0,0,0,0);const to=new Date(+from+7*864e5);
  for(let i=0;i<3;i++){ // retry network blips; never drop the saved login on a transient error
    try{const ev=await caldav.fetchEvents(c.user,c.pw,from,to);const out=ev.map(e=>({...e,start:+e.start,end:e.end?+e.end:null}));
      wr('calcache.json',{events:out,at:Date.now()});return {connected:true,events:out}}
    catch(e){if(e.message==='AUTH')return {connected:true,events:cache.events,authError:true};await new Promise(r=>setTimeout(r,2000*(i+1)))}}
  return {connected:true,events:cache.events,stale:true};});
// ---- battery: AirPods via BLE advert scan, iPhone via a Shortcut that POSTs to a local URL
const bat={pods:null,podsAt:0,iphone:null};
function startScan(){
  if(process.platform!=='win32')return;
  const p=spawn('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'lib','ble-scan.ps1')],{windowsHide:true});
  p.stdout.on('data',d=>String(d).split(/\r?\n/).forEach(l=>{const m=l.match(/^AP ([0-9A-F]+) (-?\d+)/);if(!m)return;
    const r=parseAirPods(Buffer.from(m[1],'hex'));if(r&&(+m[2]>-75)){bat.pods=r;bat.podsAt=Date.now()}}));
  p.on('exit',()=>setTimeout(startScan,15000));
  app.on('quit',()=>p.kill());
}
function startBatteryServer(){
  let tok=rd('token.json',null);if(!tok){tok={t:crypto.randomBytes(12).toString('hex')};wr('token.json',tok)}
  http.createServer((q,r)=>{const u=new URL(q.url,'http://x');
    if(u.pathname==='/iphone-battery'&&u.searchParams.get('t')===tok.t){const l=parseInt(u.searchParams.get('level'));
      if(l>=0&&l<=100){bat.iphone={level:l,charging:u.searchParams.get('charging')==='1',at:Date.now()};r.end('ok');return}}
    r.statusCode=404;r.end()}).listen(8765,'0.0.0.0').on('error',()=>{});
  return tok.t;
}
ipcMain.handle('bat:get',()=>({pods:bat.pods&&Date.now()-bat.podsAt<10*60e3?bat.pods:null,podsAge:Date.now()-bat.podsAt,iphone:bat.iphone}));

// ---- now playing via Windows media session (SMTC)
let media={none:true},mediaAt=0;const cmdFile=()=>path.join(app.getPath('temp'),'glasswidgets-media-cmd.txt');
function startMedia(){
  if(process.platform!=='win32')return;
  const p=spawn('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'lib','media.ps1'),'-CmdFile',cmdFile()],{windowsHide:true});
  let buf='';p.stdout.setEncoding('utf8');
  p.stdout.on('data',d=>{buf+=d;let i;while((i=buf.indexOf('\n'))>=0){const l=buf.slice(0,i).trim();buf=buf.slice(i+1);try{media=JSON.parse(l);mediaAt=Date.now()}catch{}}});
  p.on('exit',()=>setTimeout(startMedia,10000));app.on('quit',()=>p.kill());
}
ipcMain.handle('media:get',()=>({...media,age:Date.now()-mediaAt}));
ipcMain.handle('media:cmd',(_,c)=>{if(['toggle','next','prev','play','pause'].includes(c))fs.writeFileSync(cmdFile(),c)});
const lock=app.requestSingleInstanceLock();if(!lock)app.quit();
app.on('second-instance',()=>openSettings());
app.whenReady().then(()=>{
  if(!lock)return;
  startMedia();startScan();const batTok=startBatteryServer();
  clips=rd('clips.json',[]);lastClip=clips[0]||'';setInterval(pollClip,800);
  const en=rd('enabled.json',null);
  Object.keys(WIDGETS).forEach(id=>{if(!en||en[id]!==false)open(id)});
  openSettings(); // every launch opens the management window
  const tray=new Tray(nativeImage.createFromPath(path.join(__dirname,'..','build','tray.png')));
  tray.setToolTip('GlassWidgets');
  tray.on('click',openSettings);
  const menu=()=>Menu.buildFromTemplate([
    {label:'הגדרות…',click:openSettings},{type:'separator'},
    ...Object.keys(WIDGETS).map(id=>({label:WIDGETS[id].label,type:'checkbox',checked:!!wins[id],click:()=>{toggle(id);tray.setContextMenu(menu())}})),
    {type:'separator'},
    {label:'העתק כתובת סוללת אייפון (ל-Shortcut)',click:()=>clipboard.writeText('http://'+require('os').hostname()+':8765/iphone-battery?t='+batTok+'&level=<Battery Level>&charging=<1 or 0>')},
    {label:'תמיד מעל חלונות אחרים',type:'checkbox',checked:getSet().onTop,click:i=>{const s=getSet();s.onTop=i.checked;wr('settings.json',s);Object.values(wins).forEach(w=>w.setAlwaysOnTop(i.checked,'screen-saver'))}},
    {label:'הפעל עם ווינדוס',type:'checkbox',checked:app.getLoginItemSettings().openAtLogin,click:i=>app.setLoginItemSettings({openAtLogin:i.checked})},
    {type:'separator'},{label:'יציאה',click:()=>app.quit()}]);
  tray.setContextMenu(menu());
});
app.on('window-all-closed',e=>e.preventDefault());
