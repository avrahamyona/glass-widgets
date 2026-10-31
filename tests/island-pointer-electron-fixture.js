// Real Electron setters, synthetic own windows only. No app boot, desktop pixels, OS input or network.
const {app,BrowserWindow}=require('electron'),fs=require('fs'),vm=require('vm'),path=require('path'),os=require('os');
app.setPath('userData',fs.mkdtempSync(path.join(os.tmpdir(),'island-pointer-fixture-')));
const src=fs.readFileSync(path.join(__dirname,'../src/main.js'),'utf8');
app.whenReady().then(async()=>{const all=[],calls=[];let handler;
 const mk=async(label,x)=>{const w=new BrowserWindow({x,y:50,width:440,height:230,show:false,webPreferences:{contextIsolation:true,nodeIntegration:false}});await w.loadURL('data:text/html;charset=utf-8,'+encodeURIComponent(`<html dir="rtl"><body style="background:#171717;color:white;font:22px sans-serif;text-align:center;padding:30px"><b>${label}</b><p>בדיקה סינתטית בלבד</p><small>ללא צילום מסך או קלט למחשב</small></body></html>`));w.show();const setter=w.setIgnoreMouseEvents.bind(w);w.setIgnoreMouseEvents=(on,opt)=>{setter(on,opt);calls.push([w.webContents.id,on])};all.push(w);return w};
 const primary=await mk('אי ראשי פתוח',30),secondary=await mk('אי משני סגור',500);
 const ctx={ipcMain:{handle:(n,f)=>handler=f},islandAuditId:e=>all.some(w=>w.webContents===e.sender)?'chat':null,wins:{chat:primary},chatCompanions:new Map([[2,secondary]]),passthroughApplied:new Map(),agentAudit(){}};
 vm.runInNewContext(src.slice(src.indexOf("ipcMain.handle('chat:passthrough'"),src.indexOf("ipcMain.handle('feedback:send'")),ctx);
 handler({sender:primary.webContents},false);handler({sender:secondary.webContents},true);
 if(calls.length!==2||calls[0][0]!==primary.webContents.id||calls[0][1]!==false||calls[1][0]!==secondary.webContents.id||calls[1][1]!==true)throw Error('cross-window pointer mutation');
 await new Promise(r=>setTimeout(r,150));for(const [i,w]of all.entries())fs.writeFileSync('/downloads/island-repair/pointer-fixture-'+i+'.png',(await w.webContents.capturePage()).toPNG());
 console.log(JSON.stringify({pass:true,platform:process.platform,realElectronSetters:true,primaryInteractive:true,companionPassthrough:true,actualOsCursorTested:false,desktopCaptured:false,productionBoot:false}));for(const w of all)w.destroy();app.quit();setTimeout(()=>app.exit(0),2000).unref();
}).catch(e=>{console.error(e);app.exit(1)});
