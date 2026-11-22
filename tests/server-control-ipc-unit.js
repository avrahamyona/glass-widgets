'use strict';
const assert=require('node:assert/strict'),path=require('node:path');
const {pathToFileURL}=require('node:url');
const {registerServerControlIpc}=require('../src/lib/server-control-ipc-prep');
(async()=>{
 const handlers=new Map(),file=path.join(__dirname,'..','src','server-settings','index.html'),url=pathToFileURL(file).href,calls=[];
 const frame={url},contents={mainFrame:frame,getURL:()=>url,isDestroyed:()=>false},win={webContents:contents,isDestroyed:()=>false};
 const event={sender:contents,senderFrame:frame};
 const ipcMain={handle:(channel,fn)=>{assert(!handlers.has(channel));handlers.set(channel,fn)},removeHandler:channel=>handlers.delete(channel)};
 const registration=registerServerControlIpc({ipcMain,getManagementWindow:()=>win,settingsFile:file,control:{
  status:async()=>{calls.push('status');return {ok:true,verified:true,provisioned:true,running:false,desiredIntent:'stopped',secretPath:'must-not-leave-main'}},
  start:async()=>{calls.push('start');return {ok:true,verified:true,intent:'running'}},
  stop:async()=>{calls.push('stop');return {ok:true,verified:true,intent:'stopped'}}
 }});
 let n=0;async function test(name,fn){await fn();n++;console.log('ok '+name)}
 await test('only the exact management top frame can call status, start or stop',async()=>{for(const action of ['status','start','stop'])assert((await handlers.get('server:'+action)(event)).ok);assert.deepEqual(calls,['status','start','stop'])});
 await test('other renderer with the same URL is rejected',async()=>{const fake={...contents};assert.equal((await handlers.get('server:start')({sender:fake,senderFrame:frame})).error,'server_control_sender_rejected')});
 await test('child frame with the same URL is rejected',async()=>{assert.equal((await handlers.get('server:stop')({sender:contents,senderFrame:{url}})).error,'server_control_sender_rejected')});
 await test('navigation away from server settings is rejected',async()=>{frame.url=pathToFileURL(path.join(__dirname,'..','src','picker','index.html')).href;assert.equal((await handlers.get('server:start')(event)).error,'server_control_sender_rejected');frame.url=url});
 await test('a URL with a query or fragment is not silently upgraded to the trusted file',async()=>{frame.url=url+'#untrusted';assert.equal((await handlers.get('server:start')(event)).error,'server_control_sender_rejected');frame.url=url});
 await test('renderer parameters cannot choose a PID, session, launcher or event',async()=>{const before=calls.length;assert.equal((await handlers.get('server:stop')(event,{pid:999,event:'windows-logon'})).error,'server_control_parameters_rejected');assert.equal(calls.length,before)});
 await test('native details and paths are not returned to the renderer',async()=>{const result=await handlers.get('server:status')(event);assert.equal(result.secretPath,undefined);assert.equal(result.running,false);assert.equal(result.verified,true)});
 await test('handler removal is explicit',async()=>{registration.dispose();assert.equal(handlers.size,0)});
 console.log(JSON.stringify({checks:n,scope:'IPC origin and data-boundary harness',electronWindowRendered:false}));
})().catch(error=>{console.error(error);process.exitCode=1});
