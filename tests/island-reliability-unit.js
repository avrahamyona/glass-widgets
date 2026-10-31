// Exercise production handler/functions without Electron, a device, or real network.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync('src/main.js','utf8');
async function screenshotCase({srcs=[],throws=false,black=false}={}){
 let restored=0,hidden=0,handler;
 const start=source.indexOf("ipcMain.handle('chat:screenshot'");
 const end=source.indexOf('async function chatPage',start);
 const ctx={ipcMain:{handle:(name,fn)=>handler=fn},SHOT_URL:'http://test.invalid/shot',CHAT_DOWN:{},crypto:{randomUUID:()=> 'test'},hideChatWins:()=>{hidden++;return [{}]},showChatWins:()=>restored++,desktopCapturer:{getSources:async()=>{if(throws)throw Error('capture');return srcs}},isBlackImage:()=>black,screen:{getAllDisplays:()=>[]},setTimeout:fn=>{fn()},fetch:async()=>{throw Error('offline')}};
 vm.runInNewContext(source.slice(start,end),ctx);await handler(null,0);assert.equal(hidden,1);assert.equal(restored,1,'hidden island must always be restored');
}
async function streamResume(){
 const start=source.indexOf('async function runChatStream');const end=source.indexOf("ipcMain.handle('chat:stream'",start);let observed;const delays=[];
 const ctx={CHAT_URL:'http://test.invalid/chat',CHAT_STREAM_URL:'http://test.invalid/chat/stream',CHAT_KEY:'synthetic',chatStream:{stop:false,cursor:1234,thread:'chat'},chatCatchup:async()=>{},URL,app:{getVersion:()=> 'test'},AbortController,fetch:async u=>{observed=u;ctx.chatStream.stop=true;throw Error('end fixture')},clearTimeout:()=>{},setTimeout:(fn,ms)=>{delays.push(ms);if(ms!==8000)fn();return 1}};
 vm.runInNewContext(source.slice(start,end),ctx);await ctx.runChatStream();assert.equal(observed.searchParams.get('after'),'1234','SSE must resume at the catchup cursor, not the first50 rows');assert(delays.includes(8000),'connection headers must have bounded timeout');
}
async function stalledHeaders(){
 const start=source.indexOf('async function runChatStream');const end=source.indexOf("ipcMain.handle('chat:stream'",start);let timer,aborted=false;
 const ctx={CHAT_URL:'http://test.invalid/chat',CHAT_STREAM_URL:'http://test.invalid/chat/stream',CHAT_KEY:'synthetic',chatStream:{stop:false,cursor:0,thread:'chat'},chatCatchup:async()=>{},URL,app:{getVersion:()=> 'test'},AbortController,fetch:async(u,opts)=>new Promise((resolve,reject)=>{opts.signal.addEventListener('abort',()=>{aborted=true;ctx.chatStream.stop=true;reject(Error('timeout'))});timer()}),clearTimeout:()=>{},setTimeout:(fn,ms)=>{if(ms===8000){timer=fn}else fn();return 1}};
 vm.runInNewContext(source.slice(start,end),ctx);await ctx.runChatStream();assert(aborted,'stalled headers must abort fetch and leave loop when stopped');
}
async function catchupPages(){
 const start=source.indexOf('const chatDeliverySeen');const end=source.indexOf('async function runChatStream',start);let deliveries=0,alerts=0,calls=0;
 const rows=Array.from({length:120},(_,i)=>({id:String(i),received_at:i+1,text:'fixture',from:'agent'}));
 const ctx={Map,Math,wins:{one:{isDestroyed:()=>false,webContents:{send:()=>deliveries++}}},chatCompanions:new Map(),notifyChat:()=>alerts++,chatStream:{cursor:0},chatPage:async after=>{calls++;return {ok:true,messages:rows.filter(x=>x.received_at>after).slice(0,50),cards:[]}},broadcastCard:()=>{}};
 vm.runInNewContext(source.slice(start,end),ctx);await ctx.chatCatchup();assert.equal(ctx.chatStream.cursor,120);assert.equal(deliveries,120,'page overlap must not redeliver');assert.equal(alerts,120);assert.equal(calls,3);
}
async function duplicateReplay(){
 const start=source.indexOf('const chatDeliverySeen');const end=source.indexOf('async function chatCatchup',start);let delivered=0,toasts=0;
 const ctx={Map,wins:{one:{isDestroyed:()=>false,webContents:{send:()=>delivered++}},two:{isDestroyed:()=>false,webContents:{send:()=>delivered++}}},chatCompanions:new Map(),notifyChat:()=>toasts++};
 vm.runInNewContext(source.slice(start,end),ctx);ctx.broadcastChat({id:'one',text:'fixture'});ctx.broadcastChat({id:'one',text:'fixture'});assert.equal(delivered,2,'one delivery per screen despite replay');assert.equal(toasts,1,'one native alert despite replay');
}
(async()=>{await screenshotCase();await screenshotCase({throws:true});await screenshotCase({srcs:[{thumbnail:{isEmpty:()=>true}}]});await screenshotCase({srcs:[{thumbnail:{isEmpty:()=>false}}],black:true});await streamResume();await duplicateReplay();await catchupPages();await stalledHeaders();console.log('island-reliability-unit: 8 cases OK')})().catch(e=>{console.error(e.message);process.exit(1)});
