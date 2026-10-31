// Production IPC and renderer extraction: no installed app, desktop input or network.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const main=fs.readFileSync('src/main.js','utf8'),html=fs.readFileSync('src/widgets/chat/index.html','utf8');
function harness(){let fn;const calls=[],audit=[];const make=id=>({isDestroyed:()=>false,webContents:{id},setIgnoreMouseEvents:(on)=>calls.push([id,on])});const primary=make(1),secondary=make(2);
 const c={ipcMain:{handle:(n,f)=>fn=f},islandAuditId:e=>[primary.webContents,secondary.webContents].includes(e.sender)?'chat-main':null,wins:{'chat-main':primary},chatCompanions:new Map([[2,secondary]]),passthroughApplied:new Map(),agentAudit:r=>audit.push(r)};
 vm.runInNewContext(main.slice(main.indexOf("ipcMain.handle('chat:passthrough'"),main.indexOf("ipcMain.handle('feedback:send'")),c);return {fn,primary,secondary,calls,audit,c}}
let h=harness();h.fn({sender:h.primary.webContents},false);h.fn({sender:h.secondary.webContents},true);assert.deepEqual(h.calls,[[1,false],[2,true]],'secondary mouseleave cannot change primary open island');
h.fn({sender:h.primary.webContents},true);assert.deepEqual(h.calls.at(-1),[1,true]);assert.equal(h.calls.filter(x=>x[0]===2).length,1,'primary cannot change secondary');
assert.equal(h.fn({sender:{id:99}},true).ok,false);assert.equal(h.calls.length,3,'unknown sender cannot change windows');
h=harness();h.primary.setIgnoreMouseEvents=()=>{throw Error('destroying')};assert.equal(h.fn({sender:h.primary.webContents},true).ok,false);assert.equal(h.c.passthroughApplied.size,0,'failed apply cannot cache success');
const c={H:{messages:[{id:'own',dir:'out',status:'waiting',text:'synthetic'}],lastReceived:0},save:()=>c.saved++,paintChat:()=>c.painted++,saved:0,painted:0};
vm.runInNewContext(html.slice(html.indexOf('function incoming(m)'),html.indexOf('function incomingCard')),c);
c.incoming({id:'own',from:'user',received_at:123,text:'synthetic'});assert.equal(c.H.messages.length,1);assert.equal(c.H.lastReceived,123);assert.equal(c.H.messages[0].received_at,123);assert.equal(c.H.messages[0].status,'sent');assert.equal(c.saved,1);
c.incoming({id:'own',from:'user',received_at:123});assert.equal(c.saved,1,'same echo does not persist/rerender again');c.incoming({id:'own',from:'user',received_at:100});assert.equal(c.H.lastReceived,123,'stale echo cannot regress cursor');
c.H.messages.push({id:'reply',dir:'out',status:'sent'});c.incoming({id:'reply',from:'agent',received_at:124});assert.equal(c.H.messages[1].dir,'in');assert.equal(c.H.lastReceived,124);assert.equal(c.H.messages.length,2);
console.log('island-interaction-unit: dual-screen isolation, sender validation, failed apply, own echo metadata, replay, direction correction OK');
(async()=>{let resolvePost;const c={H:{messages:[],lastReceived:0,seenHint:true},txt:{value:'synthetic',focus(){}},replyTo:null,paintReplyBar(){},grow(){},paintChat(){},save(){},crypto:{randomUUID:()=> 'optimistic'},api:{chatSend:()=>new Promise(r=>resolvePost=r),chatSentSend(){}},hint:{style:{}}};
 vm.runInNewContext(html.slice(html.indexOf('async function doSend()'),html.indexOf("let alertPreview='';")),c);const pending=c.doSend();c.H.messages[0].received_at=456;resolvePost({ok:true,id:'optimistic'});await pending;assert.equal(c.H.messages[0].received_at,456,'POST resolution preserves earlier SSE receipt');console.log('island-send-echo: SSE-before-POST receipt preserved');})().catch(e=>{console.error(e);process.exitCode=1});
