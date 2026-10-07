const {app,BrowserWindow,Menu,Tray,nativeImage,ipcMain,clipboard,safeStorage,shell,screen,session}=require('electron');
const {spawn}=require('child_process'),http=require('http'),crypto=require('crypto');
const {parseAirPods}=require('./lib/airpods'),caldav=require('./lib/caldav'),net=require('./lib/net'),themeLib=require('./lib/theme');
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
  nowplaying:{label:'מנגן עכשיו',w:400,h:200,x:480,y:500},
  reminders:{label:'תזכורות',w:200,h:200,x:1000,y:500},
  invest:{label:'מעקב השקעות',w:260,h:360,x:780,y:500}
};
const U=()=>app.getPath('userData');
const rd=(f,d)=>{try{return JSON.parse(fs.readFileSync(path.join(U(),f)))}catch{return d}};
const wr=(f,v)=>fs.writeFileSync(path.join(U(),f),JSON.stringify(v));
const wins={};
function instances(){const saved=rd('instances.json',null);if(Array.isArray(saved))return saved.filter(x=>x&&typeof x.id==='string'&&/^[a-z0-9-]+$/.test(x.id)&&WIDGETS[x.type]);const migrated=Object.keys(WIDGETS).map(type=>({id:type,type}));wr('instances.json',migrated);return migrated}
function instance(id){return instances().find(x=>x.id===id)}
function instanceConfig(id){const it=instance(id);if(!it)return {size:WIDGETS[id]?.w>WIDGETS[id]?.h?'rectangle':'square',style:getSet().styles[id],timezone:'Asia/Jerusalem',city:getSet().city,portfolio:getSet().portfolio};const s=getSet(),local=s.instanceConfigs?.[id]||{};return {size:s.sizes[id]||((WIDGETS[it.type].w>WIDGETS[it.type].h)?'rectangle':'square'),style:s.styles[id]||s.styles[it.type],timezone:'Asia/Jerusalem',onTop:s.onTop,city:s.city,portfolio:s.portfolio,...local}}
function callerInstance(event){try{const u=new URL(event.sender.getURL()),id=u.searchParams.get('instance');return instance(id)?id:null}catch{return null}}
function instanceNoteFile(event){const id=callerInstance(event);return !id||id==='notes'?'notes.json':'notes-'+id+'.json'}

function dimensions(id){const size=instanceConfig(id).size;return size==='rectangle'?{width:400,height:200}:{width:200,height:200}}
function saveLayout(){const c=rd('layout.json',{});for(const [id,w] of Object.entries(wins)){if(!w.isDestroyed()){const [x,y]=w.getPosition();c[id]={x,y}}}wr('layout.json',c)}
function visiblePosition(x,y,width,height){const ds=screen.getAllDisplays();if(ds.some(d=>x>=d.workArea.x&&y>=d.workArea.y&&x+width<=d.workArea.x+d.workArea.width&&y+height<=d.workArea.y+d.workArea.height))return {x,y};const a=screen.getDisplayNearestPoint({x,y}).workArea;return {x:Math.max(a.x,Math.min(x,a.x+a.width-width)),y:Math.max(a.y,Math.min(y,a.y+a.height-height))}}

function open(id){
  if(wins[id]&&!wins[id].isDestroyed())return;
  const it=instance(id);if(!it)return;const d=WIDGETS[it.type],s=(rd('layout.json',{}))[id]||{};
  const dim=dimensions(id),pos=visiblePosition(s.x??d.x,s.y??d.y,dim.width,dim.height);
  const w=new BrowserWindow({...dim,...pos,frame:false,transparent:true,hasShadow:false,
    resizable:false,skipTaskbar:true,show:false,
    webPreferences:{preload:path.join(__dirname,'preload.js'),contextIsolation:true,nodeIntegration:false}});
  w.loadFile(path.join(__dirname,'widgets',instance(id).type,'index.html'),{query:wq(id)});
  w.once('ready-to-show',()=>{w.show();if(instanceConfig(id).onTop)w.setAlwaysOnTop(true,'screen-saver')});
  w.on('move',saveLayout);w.on('moved',saveLayout);w.on('close',saveLayout);
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
ipcMain.handle('notes:get',e=>rd(instanceNoteFile(e),{text:''}).text);
ipcMain.handle('notes:save',(e,t)=>{wr(instanceNoteFile(e),{text:String(t).slice(0,20000)})});
let clips=[];let lastClip='';
function pollClip(){const t=clipboard.readText();
  if(t&&t!==lastClip){lastClip=t;clips=[t,...clips.filter(x=>x!==t)].slice(0,30);wr('clips.json',clips);
    Object.values(wins).forEach(w=>w.webContents.send('clip:update',clips))}}
ipcMain.handle('clip:list',()=>clips);
ipcMain.handle('clip:copy',(_,t)=>{lastClip=t;clipboard.writeText(t)});
ipcMain.handle('clip:clear',()=>{clips=[];wr('clips.json',clips);Object.values(wins).forEach(w=>w.webContents.send('clip:update',clips))});
ipcMain.handle('cfg:get',e=>{const id=callerInstance(e),c=id?instanceConfig(id).city:getSet().city;return c?{...CITY,...c}:CITY});


// ---- settings (theme, per-widget style, general)
const DEF={instanceConfigs:{},sizes:{},theme:'auto',onTop:false,styles:{clock:'analog',sysmon:'rings',notes:'yellow'},city:null,portfolio:[{sym:'^GSPC',qty:0},{sym:'AAPL',qty:0},{sym:'TA35.TA',qty:0}]};
const getSet=()=>{const s=rd('settings.json',{});return {...DEF,...s,instanceConfigs:s.instanceConfigs||{},sizes:{...DEF.sizes,...(s.sizes||{})},styles:{...DEF.styles,...(s.styles||{})}}};
function currentTheme(){const s=getSet();const city=s.city||CITY;const t=themeLib.effectiveTheme(s.theme,new Date(),city.lat,city.lon);return t==='system'?null:t}
function wq(id){const s=getSet(),c=instanceConfig(id),q={size:c.size,id:instance(id).type,instance:id,tz:c.timezone};const t=currentTheme();if(t)q.theme=t;else if(s.theme!=='auto'&&s.theme!=='system')q.theme=s.theme;if(c.style)q.style=c.style;return q}
ipcMain.handle('theme:get',()=>currentTheme()||'system');
function reload(id){const w=wins[id];if(w)w.loadFile(path.join(__dirname,'widgets',instance(id).type,'index.html'),{query:wq(id)})}
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
  widgetTypes:Object.entries(WIDGETS).map(([type,w])=>({type,label:w.label})),widgets:instances().map((it,i)=>({id:it.id,type:it.type,label:WIDGETS[it.type].label+' '+(instances().filter(x=>x.type===it.type).findIndex(x=>x.id===it.id)+1),on:!!wins[it.id],...instanceConfig(it.id)})),
  autostart:app.getLoginItemSettings().openAtLogin,version:app.getVersion()}});
ipcMain.handle('set:toggle',(_,id,on)=>{if(!instance(id))return;if(on&&!wins[id])open(id);else if(!on&&wins[id])toggle(id);return !!wins[id]});
ipcMain.handle('instance:add',(_,type,source)=>{if(!WIDGETS[type])return {error:'סוג כרטיס לא מוכר'};const list=instances();if(list.length>=60)return {error:'אפשר עד 60 כרטיסים'};const id=type+'-'+crypto.randomUUID();list.push({id,type});wr('instances.json',list);const cur=getSet(),cfg=source&&instance(source)?.type===type?instanceConfig(source):instanceConfig(list.find(x=>x.type===type&&x.id!==id)?.id||type);cur.instanceConfigs[id]=JSON.parse(JSON.stringify(cfg));wr('settings.json',cur);const layout=rd('layout.json',{}),base=layout[source]||WIDGETS[type];layout[id]={x:(base.x||60)+28,y:(base.y||60)+28};wr('layout.json',layout);if(type==='notes')wr('notes-'+id+'.json',rd(source==='notes'||!source?'notes.json':'notes-'+source+'.json',{text:''}));open(id);return {ok:true,id}});
ipcMain.handle('instance:remove',(_,id)=>{if(!instance(id))return {ok:false};if(wins[id])wins[id].close();wr('instances.json',instances().filter(x=>x.id!==id));for(const file of ['layout.json','enabled.json']){const val=rd(file,{});delete val[id];wr(file,val)}const s=getSet();delete s.instanceConfigs[id];delete s.sizes[id];delete s.styles[id];wr('settings.json',s);return {ok:true}});
ipcMain.handle('instance:save',(_,id,patch)=>saveInstance(id,patch));
ipcMain.handle('instance:self',e=>{const id=callerInstance(e);return id?{id,...instanceConfig(id)}:null});
ipcMain.handle('instance:self-save',(e,patch)=>{const id=callerInstance(e);return id?saveInstance(id,patch):{ok:false}});
function saveInstance(id,patch){if(!instance(id)||!patch||typeof patch!=='object')return {ok:false};const safe={};if(['square','rectangle'].includes(patch.size))safe.size=patch.size;if(typeof patch.style==='string')safe.style=patch.style.slice(0,20);if(typeof patch.timezone==='string'){try{new Intl.DateTimeFormat('en',{timeZone:patch.timezone});safe.timezone=patch.timezone}catch{return {ok:false,error:'אזור זמן לא מוכר'}}}if(Array.isArray(patch.portfolio))safe.portfolio=patch.portfolio.slice(0,30).filter(x=>x&&typeof x.sym==='string').map(x=>({sym:x.sym.slice(0,30),name:String(x.name||'').slice(0,150),qty:+x.qty||0}));if(patch.city&&Number.isFinite(patch.city.lat)&&Number.isFinite(patch.city.lon))safe.city={name:String(patch.city.name||'').slice(0,100),lat:patch.city.lat,lon:patch.city.lon};if(typeof patch.onTop==='boolean')safe.onTop=patch.onTop;if(typeof patch.noteId==='string')safe.noteId=patch.noteId.slice(0,200);const s=getSet();s.instanceConfigs[id]={...s.instanceConfigs[id],...safe};wr('settings.json',s);if(wins[id]){if(safe.onTop!==undefined)wins[id].setAlwaysOnTop(safe.onTop,'screen-saver');if(safe.size){const d=dimensions(id),w=wins[id];w.setResizable(true);w.setMinimumSize(0,0);w.setMaximumSize(0,0);w.setBounds({...w.getBounds(),...d});w.setResizable(false);const [x,y]=w.getPosition();w.setPosition(...Object.values(visiblePosition(x,y,d.width,d.height)));saveLayout()}reload(id);wins[id].show();wins[id].moveTop()}return {ok:true,settings:getSet()}}
ipcMain.handle('set:save',(_,patch)=>{const cur=getSet();const next={...cur,...patch,instanceConfigs:cur.instanceConfigs,sizes:{...cur.sizes,...(patch.sizes||{})},styles:{...cur.styles,...(patch.styles||{})}};wr('settings.json',next);
  const themeChanged=next.theme!==cur.theme;
  for(const id of Object.keys(wins)){if(patch.sizes&&patch.sizes[id]){next.instanceConfigs[id]={...next.instanceConfigs[id],size:patch.sizes[id]};wr('settings.json',next);const dim=dimensions(id);wins[id].setResizable(true);wins[id].setMinimumSize(0,0);wins[id].setMaximumSize(0,0);wins[id].setBounds({...wins[id].getBounds(),width:dim.width,height:dim.height});wins[id].setResizable(false);const [x,y]=wins[id].getPosition();const pos=visiblePosition(x,y,dim.width,dim.height);wins[id].setPosition(pos.x,pos.y);reload(id);wins[id].show();wins[id].moveTop()}if(patch.styles?.[id]!==undefined){next.instanceConfigs[id]={...next.instanceConfigs[id],style:patch.styles[id]};wr('settings.json',next)}if(themeChanged||patch.styles?.[id]!==undefined||(instance(id).type==='weather'&&patch.city!==undefined)||(instance(id).type==='invest'&&patch.portfolio!==undefined))reload(id)}
  if(patch.onTop!==undefined)Object.entries(wins).forEach(([id,w])=>w.setAlwaysOnTop(!!instanceConfig(id).onTop,'screen-saver'));
  if(patch.autostart!==undefined)app.setLoginItemSettings({openAtLogin:!!patch.autostart});
  return next});
// ---- investments (Yahoo chart endpoint, no key)
const stockQuoteCache=new Map();
async function quote(sym){const key=String(sym).trim().toUpperCase();const old=stockQuoteCache.get(key);if(old&&Date.now()-old.at<60000)return old.promise;const promise=fetchQuote(key);stockQuoteCache.set(key,{at:Date.now(),promise});if(stockQuoteCache.size>100)stockQuoteCache.delete(stockQuoteCache.keys().next().value);return promise}
async function fetchQuote(sym){
  const r=await fetch('https://query1.finance.yahoo.com/v8/finance/chart/'+encodeURIComponent(sym)+'?interval=1d&range=5d',{headers:{'User-Agent':'Mozilla/5.0'}});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const j=await r.json(),res=j.chart&&j.chart.result&&j.chart.result[0];if(!res)throw new Error('not found');
  const mt=res.meta,cl=((res.indicators&&res.indicators.quote&&res.indicators.quote[0].close)||[]).filter(x=>x!=null);
  const price=mt.regularMarketPrice;let prev=cl.length>=2?cl[cl.length-2]:mt.chartPreviousClose;
  if(cl.length>=2&&Math.abs(cl[cl.length-1]-price)>price*0.2)prev=cl[cl.length-1];
  let pct=prev?((price-prev)/prev)*100:(mt.regularMarketChangePercent||0);
  return {sym,name:mt.shortName||mt.longName||sym,price,pct,cur:mt.currency||'',chart:cl.slice(-50)};
}
ipcMain.handle('inv:get',async e=>{
  const id=callerInstance(e),list=(id?instanceConfig(id).portfolio:getSet().portfolio)||[];
  const out=await Promise.all(list.map(async p=>{try{return {...(await quote(p.sym)),qty:+p.qty||0}}catch(e){return {sym:p.sym,qty:+p.qty||0,error:e.message}}}));
  return out});
const stockSearchCache=new Map();let stockSearchBackoff=0;
function stockFailure(e){const msg=String(e?.message||'');return msg.includes('429')?'ספק הנתונים הגביל בקשות. המתן דקה ונסה שוב.':msg.includes('404')?'לא נמצאו נתונים לסימול הזה כרגע.':'לא ניתן להגיע לספק הנתונים כרגע. נסה שוב מאוחר יותר.'}
ipcMain.handle('inv:search',async(_,query)=>{
 const q=String(query||'').trim().slice(0,80);if(q.length<2)return {items:[]};
 const cached=stockSearchCache.get(q.toLowerCase());if(cached&&Date.now()-cached.at<300000)return {items:cached.items};
 if(Date.now()<stockSearchBackoff)return {items:[],error:'ספק החיפוש הגביל בקשות. המתן דקה ונסה שוב.'};
 try{const r=await fetch('https://query1.finance.yahoo.com/v1/finance/search?q='+encodeURIComponent(q)+'&quotesCount=8&newsCount=0',{headers:{'User-Agent':'Mozilla/5.0'},signal:AbortSignal.timeout(10000)});
 if(r.status===429){stockSearchBackoff=Date.now()+60000;throw new Error('HTTP 429')}if(!r.ok)throw new Error('HTTP '+r.status);
 const j=await r.json(),items=(j.quotes||[]).filter(x=>x.symbol&&['EQUITY','ETF','INDEX','MUTUALFUND'].includes(x.quoteType)).slice(0,8).map(x=>({sym:String(x.symbol),name:String(x.shortname||x.longname||x.symbol),exchange:String(x.exchDisp||x.exchange||''),type:String(x.quoteType)}));
 stockSearchCache.set(q.toLowerCase(),{at:Date.now(),items});if(stockSearchCache.size>50)stockSearchCache.delete(stockSearchCache.keys().next().value);return {items};
 }catch(e){return {items:[],error:stockFailure(e)}}});
ipcMain.handle('inv:check',async(_,sym)=>{try{const q=await quote(String(sym).trim());return {ok:true,name:q.name}}catch(e){return {ok:false,error:stockFailure(e)}}});
// ---- network
ipcMain.handle('inv:open',(_,sym)=>{sym=String(sym||'').trim();if(!/^[A-Za-z0-9.^=-]{1,20}$/.test(sym))return {ok:false};shell.openExternal('https://finance.yahoo.com/quote/'+encodeURIComponent(sym));return {ok:true}});
ipcMain.handle('net:get',()=>net.get());
// ---- calendar (iCloud CalDAV; app-specific password kept encrypted with the OS)
const credFile='cal.bin';
function loadCreds(){try{const b=fs.readFileSync(path.join(U(),credFile));return JSON.parse(safeStorage.isEncryptionAvailable()?safeStorage.decryptString(b):null)}catch{return null}}
ipcMain.handle('cal:status',()=>({connected:cloudData.connected||!!loadCreds()||!!cloudData.calendar?.length}));
ipcMain.handle('cal:connect',async(_,user,pw)=>{user=String(user).trim();pw=String(pw).replace(/\s+/g,'');
  try{await caldav.fetchEvents(user,String(pw).replace(/\s+/g,''),new Date(),new Date(Date.now()+864e5));
    if(!safeStorage.isEncryptionAvailable())throw new Error('Windows לא מאפשר שמירת סיסמה מוצפנת');const j=JSON.stringify({user,pw});fs.writeFileSync(path.join(U(),credFile),safeStorage.encryptString(j));return {ok:true}}
  catch(e){return {ok:false,error:caldav.explain(e)}}});
ipcMain.handle('cal:disconnect',()=>{try{fs.unlinkSync(path.join(U(),credFile))}catch{}});
ipcMain.handle('cal:events',async()=>{if(cloudData.connected||cloudData.calendar?.length)return {connected:true,events:cloudData.calendar||[],stale:!cloudData.connected||Date.now()-(cloudData.at||0)>3600000,error:cloudData.errors?.calendar,manual:true};const c=loadCreds();if(!c)return {connected:false,events:[]};
  const cache=rd('calcache.json',{events:[]});
  const from=new Date(Date.now()-864e5);const to=new Date(+from+7*864e5);
  for(let i=0;i<3;i++){ // retry network blips; never drop the saved login on a transient error
    try{const ev=await caldav.fetchEvents(c.user,c.pw,from,to);const out=ev.map(e=>({...e,start:+e.start,end:e.end?+e.end:null}));
      wr('calcache.json',{events:out,at:Date.now()});return {connected:true,events:out}}
    catch(e){if(e.kind==='AUTH')return {connected:true,events:cache.events,authError:true,error:caldav.explain(e)};await new Promise(r=>setTimeout(r,2000*(i+1)))}}
  return {connected:true,events:cache.events,stale:true};});
// ---- battery: AirPods via BLE advert scan, iPhone via a Shortcut that POSTs to a local URL
const bat={pods:null,podsAt:0,iphone:null};
function startScan(){
  if(process.platform!=='win32')return;
  const p=spawn('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',psFile('ble-scan.ps1')],{windowsHide:true});
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
let media={none:true},mediaAt=0,mediaProcess=null,quitting=false;
function psFile(name){const d=path.join(app.getPath('temp'),'glasswidgets-ps');fs.mkdirSync(d,{recursive:true});const f=path.join(d,name);fs.writeFileSync(f,'\ufeff'+fs.readFileSync(path.join(__dirname,'lib',name),'utf8'));return f}
function startMedia(){
 if(process.platform!=='win32'||quitting)return;
 const exe=app.isPackaged?path.join(process.resourcesPath,'media','MediaBridge.exe'):path.join(__dirname,'..','native','MediaBridge','publish','MediaBridge.exe');
 if(!fs.existsSync(exe)){media={none:true,err:'רכיב המדיה חסר. התקן מחדש את הגרסה האחרונה'};return}
 const p=spawn(exe,[],{windowsHide:true,stdio:['pipe','pipe','pipe']});mediaProcess=p;
 p.on('error',e=>{media={none:true,err:e.message}});p.stderr.on('data',d=>{media={none:true,err:String(d).slice(-200)}});
 let buf='';p.stdout.setEncoding('utf8');p.stdout.on('data',d=>{buf+=d;let i;while((i=buf.indexOf('\n'))>=0){const line=buf.slice(0,i);buf=buf.slice(i+1);try{media=JSON.parse(line.replace(/^\ufeff/,''));mediaAt=Date.now()}catch{}}});
 p.on('exit',()=>{mediaProcess=null;if(!quitting)setTimeout(startMedia,10000)});
}
ipcMain.handle('media:get',()=>({...media,age:Date.now()-mediaAt}));
ipcMain.handle('media:cmd',(_,c)=>{if(!['toggle','next','prev','play','pause'].includes(c))return {ok:false};if(!mediaProcess||!mediaProcess.stdin.writable)return {ok:false,error:'רכיב המדיה אינו זמין'};mediaProcess.stdin.write(c+'\n');return {ok:true}});
// ---- user feedback to the fixes center (Avi Music Cloudflare worker, separate path/table)
const FEEDBACK_URL='https://avi-music-account-staging.avi-music.workers.dev/glasswidgets/report';
ipcMain.handle('feedback:send',async(_,text)=>{text=String(text||'').trim();if(text.length<2)return {ok:false,error:'כתוב כמה מילים לפני השליחה'};if(text.length>2000)return {ok:false,error:'ההודעה ארוכה מדי (עד 2000 תווים)'};
 try{const r=await fetch(FEEDBACK_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app:'glasswidgets',version:app.getVersion(),text,at:Date.now()}),signal:AbortSignal.timeout(15000)});
  if(!r.ok)return {ok:false,error:'השרת לא קיבל את הדיווח ('+r.status+'). נסה שוב מאוחר יותר'};return {ok:true}}
 catch{return {ok:false,error:'אין חיבור כרגע. הדיווח לא נשלח'}}});
// Official web apps share one persistent login. Remote content gets no application preload.
const ICLOUD={notes:'https://www.icloud.com/notes/',calendar:'https://www.icloud.com/calendar/',reminders:'https://www.icloud.com/reminders/',home:'https://www.icloud.com/'};
let cloudWin=null;
function allowedCloud(url){try{const u=new URL(url);return u.protocol==='https:'&&(/(^|\.)icloud\.com$/.test(u.hostname)||/(^|\.)apple\.com$/.test(u.hostname))}catch{return false}}
function openCloud(section){const url=ICLOUD[section]||ICLOUD.home;
 if(!cloudWin){cloudWin=new BrowserWindow({width:1100,height:800,title:'iCloud',autoHideMenuBar:true,webPreferences:{partition:'persist:icloud',contextIsolation:true,nodeIntegration:false,sandbox:true}});
 cloudWin.webContents.setWindowOpenHandler(({url})=>{if(allowedCloud(url)){cloudWin.loadURL(url);return {action:'deny'}}return {action:'deny'}});
 cloudWin.webContents.on('will-navigate',(event,url)=>{if(!allowedCloud(url))event.preventDefault()});cloudWin.on('closed',()=>cloudWin=null)}
 cloudWin.loadURL(url);cloudWin.show();cloudWin.focus();return {ok:true}}
ipcMain.handle('cloud:open',(_,section)=>openCloud(section));
ipcMain.handle('cloud:status',async()=>{const cookies=await session.fromPartition('persist:icloud').cookies.get({domain:'.icloud.com'});return {savedSession:cookies.some(c=>c.name.toLowerCase().includes('auth'))}});
ipcMain.handle('cloud:logout',async()=>{if(cloudWin)cloudWin.close();await session.fromPartition('persist:icloud').clearStorageData();return {ok:true}});
ipcMain.handle('cloud:chrome',(_,section)=>{const url=ICLOUD[section];if(!url)return {ok:false};
 if(process.platform==='win32'){const roots=[process.env.PROGRAMFILES,process.env['PROGRAMFILES(X86)'],process.env.LOCALAPPDATA].filter(Boolean);const exe=roots.map(r=>path.join(r,'Google','Chrome','Application','chrome.exe')).find(f=>fs.existsSync(f));if(exe){const p=spawn(exe,[url],{detached:true,stdio:'ignore'});p.unref();return {ok:true}}}
 shell.openExternal(url);return {ok:true,fallback:true}});
ipcMain.handle('settings:open',()=>openSettings());
ipcMain.handle('widgets:show',()=>{for(const w of Object.values(wins)){if(!w.isDestroyed()){w.show();w.moveTop()}}return {ok:true,count:Object.keys(wins).length}});
app.on('before-quit',()=>{quitting=true;saveLayout();stopCloud();if(mediaProcess)mediaProcess.kill()});
// Experimental, manual-refresh-only local iCloud data adapter.
let cloudTemp=null;
let cloudProcess=null,cloudSeq=0,cloudPending=new Map(),cloudData={connected:false,notes:[],reminders:[]},cloudLastRefresh=0,cloudRefreshing=false;
function encryptedRead(file){try{if(!safeStorage.isEncryptionAvailable())return null;return JSON.parse(safeStorage.decryptString(fs.readFileSync(path.join(U(),file))))}catch{return null}}
function encryptedWrite(file,data){if(!safeStorage.isEncryptionAvailable())throw new Error('Windows לא מאפשר שמירה מוצפנת');fs.writeFileSync(path.join(U(),file),safeStorage.encryptString(JSON.stringify(data)))}
function stopCloud(){const old=cloudProcess;cloudProcess=null;if(old)old.kill();if(cloudTemp){try{fs.rmSync(cloudTemp,{recursive:true,force:true})}catch{}cloudTemp=null}for(const {resolve,timer} of cloudPending.values()){clearTimeout(timer);resolve({connected:false,state:'error',error:'רכיב iCloud נעצר'})}cloudPending.clear()}
function ensureCloud(){
 if(cloudProcess)return true;if(process.platform!=='win32'&&!process.env.GLASSWIDGETS_CLOUD_PYTHON)return false;
 let exe,args=[];
 if(process.env.GLASSWIDGETS_CLOUD_PYTHON){exe=process.env.GLASSWIDGETS_CLOUD_PYTHON;args=[path.join(__dirname,'..','native','CloudBridge','bridge.py')]}else exe=app.isPackaged?path.join(process.resourcesPath,'cloud','CloudBridge','CloudBridge.exe'):path.join(__dirname,'..','native','CloudBridge','publish','CloudBridge','CloudBridge.exe');
 if(!fs.existsSync(exe))return false;
 cloudTemp=fs.mkdtempSync(path.join(app.getPath('temp'),'glasswidgets-cloud-'));
 const current=spawn(exe,args,{windowsHide:true,stdio:['pipe','pipe','pipe'],env:{...process.env,PYTHONIOENCODING:'utf-8',PYTHONUTF8:'1',GLASSWIDGETS_CLOUD_TEMP:cloudTemp}});cloudProcess=current;let buf='';current.stdout.setEncoding('utf8');current.stdout.on('data',d=>{buf+=d;let i;while((i=buf.indexOf('\n'))>=0){const line=buf.slice(0,i);buf=buf.slice(i+1);try{const o=JSON.parse(line),pending=cloudPending.get(o.id);if(o._session?.user)encryptedWrite('cloud-session.bin',o._session);delete o._session;delete o.id;if(pending){clearTimeout(pending.timer);cloudPending.delete(pending.id);pending.resolve(o)}}catch{}}});
 current.on('error',()=>{if(cloudProcess===current)stopCloud()});current.on('exit',()=>{if(cloudProcess===current)stopCloud()});current.stderr.on('data',()=>{});return true;
}
function cloudRequest(action,data={}){if(!ensureCloud())return Promise.resolve({connected:false,state:'unavailable',error:'רכיב iCloud חסר. התקן את הגרסה המלאה'});return new Promise(resolve=>{const id=++cloudSeq;const timer=setTimeout(()=>{cloudPending.delete(id);resolve({connected:false,state:'error',error:'iCloud לא ענה בזמן. לא בוצעו שינויים'});stopCloud()},120000);cloudPending.set(id,{id,resolve,timer});cloudProcess.stdin.write(JSON.stringify({id,action,...data})+'\n')})}
async function cloudResume(){if(!cloudProcess){const saved=encryptedRead('cloud-session.bin');if(saved){const r=await cloudRequest('resume',{session:saved});cloudData={...cloudData,...r};return r}}return cloudRequest('status')}
async function refreshCloud(){if(cloudRefreshing)return {...cloudData,busy:true};if(Date.now()-cloudLastRefresh<60000)return {...cloudData,cooldown:true};cloudRefreshing=true;cloudLastRefresh=Date.now();try{const s=await cloudResume();if(!s.connected){cloudData={...cloudData,...s};return cloudData}const r=await cloudRequest('refresh');cloudData={...cloudData,...r};if(r.connected){const old=encryptedRead('cloud-cache.bin')||{};cloudData.notes=r.errors?.notes?(old.notes||[]):r.notes;cloudData.reminders=r.errors?.reminders?(old.reminders||[]):r.reminders;cloudData.calendar=r.errors?.calendar?(old.calendar||[]):r.calendar;encryptedWrite('cloud-cache.bin',cloudData)}return cloudData}finally{cloudRefreshing=false}}
ipcMain.handle('icloud:status',()=>({saved:!!encryptedRead('cloud-session.bin'),state:cloudData.state||'signed_out',connected:cloudData.connected,at:cloudData.at||null,calendar:!!loadCreds(),errors:cloudData.errors||{},counts:{notes:cloudData.notes?.length||0,reminders:cloudData.reminders?.length||0,calendar:cloudData.calendar?.length||0}}));
ipcMain.handle('icloud:login',async(_,user,password)=>{stopCloud();cloudData={connected:false,notes:[],reminders:[]};cloudLastRefresh=0;const r=await cloudRequest('login',{user:String(user).trim(),password:String(password)});cloudData={...cloudData,...r};return r});
ipcMain.handle('icloud:request-code',async()=>{const r=await cloudRequest('request_code');cloudData={...cloudData,...r};return r});
ipcMain.handle('icloud:code',async(_,code,manual)=>{const r=await cloudRequest('code',{code:String(code).trim(),manual:!!manual});cloudData={...cloudData,...r};return r});
ipcMain.handle('icloud:refresh',()=>refreshCloud());
ipcMain.handle('icloud:data',()=>({...cloudData,stale:!cloudData.connected||!cloudData.at||Date.now()-cloudData.at>3600000}));
ipcMain.handle('icloud:forget',()=>{stopCloud();for(const f of ['cloud-session.bin','cloud-cache.bin']){try{fs.unlinkSync(path.join(U(),f))}catch{}}cloudData={connected:false,notes:[],reminders:[]};return {ok:true}});

// ---- self update from GitHub Releases (manual check from the settings window)
const upd={state:'idle',percent:0,version:null,error:null};
let updWired=false;
function wireUpdater(){
 if(updWired)return true;if(!app.isPackaged)return false;
 try{
  const {autoUpdater}=require('electron-updater');
  autoUpdater.autoDownload=true;autoUpdater.autoInstallOnAppQuit=true;
  autoUpdater.on('update-available',i=>{upd.state='downloading';upd.version=i.version;upd.percent=0;upd.error=null});
  autoUpdater.on('update-not-available',()=>{upd.state='none';upd.error=null});
  autoUpdater.on('download-progress',p=>{upd.state='downloading';upd.percent=Math.round(p.percent)});
  autoUpdater.on('update-downloaded',i=>{upd.state='ready';upd.version=i.version;upd.percent=100});
  autoUpdater.on('error',e=>{upd.state='error';upd.error='לא ניתן לבדוק עדכונים כרגע. נסה שוב מאוחר יותר'});
  updWired=true;return true;
 }catch{return false}
}
ipcMain.handle('update:check',()=>{if(!wireUpdater())return {state:'unavailable',error:'בדיקת עדכונים פועלת רק בגרסה המותקנת, לא בפיתוח'};upd.state='checking';upd.error=null;require('electron-updater').autoUpdater.checkForUpdates().catch(()=>{upd.state='error';upd.error='לא ניתן לבדוק עדכונים כרגע. נסה שוב מאוחר יותר'});return upd});
ipcMain.handle('update:state',()=>upd);
ipcMain.handle('update:install',()=>{if(upd.state==='ready'&&updWired){require('electron-updater').autoUpdater.quitAndInstall();return {ok:true}}return {ok:false}});
const lock=app.requestSingleInstanceLock();if(!lock)app.quit();
app.on('second-instance',()=>openSettings());
app.whenReady().then(()=>{
  if(!lock)return;
  const cached=encryptedRead('cloud-cache.bin');if(cached)cloudData={...cached,connected:false,state:'cached'};
  startMedia();startScan();const batTok=startBatteryServer();
  clips=rd('clips.json',[]);lastClip=clips[0]||'';setInterval(pollClip,800);
  const en=rd('enabled.json',null);
  instances().forEach(({id})=>{if(!en||en[id]!==false)open(id)});
  openSettings(); // every launch opens the management window
  const tray=new Tray(nativeImage.createFromPath(path.join(__dirname,'..','build','tray.png')));
  tray.setToolTip('GlassWidgets');
  tray.on('click',openSettings);
  const menu=()=>Menu.buildFromTemplate([
    {label:'הגדרות…',click:openSettings},{type:'separator'},
    ...instances().map(({id,type})=>({label:WIDGETS[type].label+' · '+id.slice(-6),type:'checkbox',checked:!!wins[id],click:()=>{toggle(id);tray.setContextMenu(menu())}})),
    {type:'separator'},
    {label:'העתק כתובת סוללת אייפון (ל-Shortcut)',click:()=>clipboard.writeText('http://'+require('os').hostname()+':8765/iphone-battery?t='+batTok+'&level=<Battery Level>&charging=<1 or 0>')},
    {label:'תמיד מעל חלונות אחרים',type:'checkbox',checked:getSet().onTop,click:i=>{const s=getSet();s.onTop=i.checked;wr('settings.json',s);Object.values(wins).forEach(w=>w.setAlwaysOnTop(i.checked,'screen-saver'))}},
    {label:'הפעל עם ווינדוס',type:'checkbox',checked:app.getLoginItemSettings().openAtLogin,click:i=>app.setLoginItemSettings({openAtLogin:i.checked})},
    {type:'separator'},{label:'יציאה',click:()=>app.quit()}]);
  tray.setContextMenu(menu());
});
app.on('window-all-closed',e=>e.preventDefault());
