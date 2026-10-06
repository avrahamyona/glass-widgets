const {app,BrowserWindow,Menu,Tray,nativeImage,ipcMain,clipboard}=require('electron');
const path=require('path'),fs=require('fs'),os=require('os');
const TZ='Asia/Jerusalem';
const CITY={name:'פתח תקווה',lat:32.0840,lon:34.8878,tz:TZ};
// 170px card + 14px margin each side for the shadow
const WIDGETS={
  clock:{label:'Clock',w:200,h:200,x:60,y:60},
  weather:{label:'Weather',w:200,h:200,x:280,y:60},
  notes:{label:'Notes',w:200,h:200,x:500,y:60},
  sysmon:{label:'System Monitor',w:400,h:200,x:60,y:280},
  clipboard:{label:'Clipboard History',w:260,h:400,x:480,y:280}
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
  w.loadFile(path.join(__dirname,'widgets',id,'index.html'));
  w.once('ready-to-show',()=>w.show());
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
ipcMain.handle('cfg:get',()=>CITY);
const lock=app.requestSingleInstanceLock();if(!lock)app.quit();
app.whenReady().then(()=>{
  clips=rd('clips.json',[]);lastClip=clips[0]||'';setInterval(pollClip,800);
  const en=rd('enabled.json',null);
  Object.keys(WIDGETS).forEach(id=>{if(!en||en[id]!==false)open(id)});
  const tray=new Tray(nativeImage.createFromPath(path.join(__dirname,'..','build','tray.png')));
  tray.setToolTip('GlassWidgets');
  const menu=()=>Menu.buildFromTemplate([
    ...Object.keys(WIDGETS).map(id=>({label:WIDGETS[id].label,type:'checkbox',checked:!!wins[id],click:()=>{toggle(id);tray.setContextMenu(menu())}})),
    {type:'separator'},
    {label:'Keep on top of other windows',type:'checkbox',click:i=>Object.values(wins).forEach(w=>w.setAlwaysOnTop(i.checked,'screen-saver'))},
    {label:'Start with Windows',type:'checkbox',checked:app.getLoginItemSettings().openAtLogin,click:i=>app.setLoginItemSettings({openAtLogin:i.checked})},
    {type:'separator'},{label:'Quit',click:()=>app.quit()}]);
  tray.setContextMenu(menu());
});
app.on('window-all-closed',e=>e.preventDefault());
