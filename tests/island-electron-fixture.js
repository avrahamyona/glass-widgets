// Isolated fixture: imports no production app boot or settings. Only exact extracted functions.
const {app,BrowserWindow}=require('electron');const fs=require('fs'),vm=require('vm'),http=require('http'),os=require('os'),path=require('path');
app.setPath('userData',fs.mkdtempSync(path.join(os.tmpdir(),'island-fixture-')));app.setName('IslandLocalReliabilityFixture');
const source=fs.readFileSync(path.join(__dirname,'../src/main.js'),'utf8');
app.whenReady().then(async()=>{
 const w=new BrowserWindow({width:520,height:270,show:false,webPreferences:{nodeIntegration:false,contextIsolation:true}});
 await w.loadURL('data:text/html;charset=utf-8,'+encodeURIComponent('<html dir="rtl"><body style="margin:0;background:#eee;font:22px sans-serif"><div style="margin:35px;background:#171717;color:white;border-radius:30px;padding:26px;text-align:center">בדיקת אי מקומית<br><small>חלון הבדיקה חזר לאחר כשל צילום</small></div></body></html>'));
 w.show();let handler;
 const ctx={ipcMain:{handle:(n,f)=>handler=f},SHOT_URL:'http://127.0.0.1:1',CHAT_DOWN:{},crypto:{randomUUID:()=> 'fixture'},hideChatWins:()=>{w.hide();return [{w}]},showChatWins:hidden=>hidden.forEach(x=>x.w.show()),desktopCapturer:{getSources:async()=>[]},setTimeout,screen:{getAllDisplays:()=>[]}};
 vm.runInNewContext(source.slice(source.indexOf("ipcMain.handle('chat:screenshot'"),source.indexOf('async function chatPage')),ctx);
 const result=await handler(null,0);if(result.ok!==false||!w.isVisible())throw Error('visibility restoration failed');
 const png=await w.webContents.capturePage();fs.writeFileSync('/downloads/island-repair/fixture-restored.png',png.toPNG());
 let cursor='',rows=0;const server=http.createServer((req,res)=>{cursor=new URL(req.url,'http://127.0.0.1').searchParams.get('after');res.writeHead(200,{'content-type':'text/event-stream'});res.end('data: '+JSON.stringify({id:'fixture',text:'synthetic',from:'agent',received_at:1235})+'\n\n')});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;
 const streamCtx={CHAT_URL:'http://127.0.0.1:'+port+'/chat',CHAT_STREAM_URL:'http://127.0.0.1:'+port+'/chat/stream',CHAT_KEY:'synthetic',chatStream:{stop:false,cursor:1234,thread:'fixture'},chatCatchup:async()=>{},URL,app:{getVersion:()=> 'fixture'},AbortController,TextDecoder,fetch,clearTimeout,setTimeout,broadcastChat:()=>{rows++;streamCtx.chatStream.stop=true}};
 vm.runInNewContext(source.slice(source.indexOf('async function runChatStream'),source.indexOf("ipcMain.handle('chat:stream'")),streamCtx);await streamCtx.runChatStream();await new Promise(r=>server.close(r));
 if(cursor!=='1234'||rows!==1)throw Error('real stream resume failed');
 console.log(JSON.stringify({fixture:'PASS',platform:process.platform,visibilityRestored:w.isVisible(),sseCursor:cursor,syntheticRows:rows,actualDesktopCaptured:false,productionBootImported:false}));w.destroy();app.quit();setTimeout(()=>app.exit(0),2000).unref();
}).catch(e=>{console.error(e.message);app.exit(1)});
