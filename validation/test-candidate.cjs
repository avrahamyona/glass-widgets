'use strict';
// Tests the candidate source directly. Only in-memory fixtures, no user data or Electron launch.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const manifest=require('./source-hashes.json');
for(const [file,expected]of Object.entries(manifest))assert.equal(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),expected,'reviewed_source_hash:'+file);
const main=fs.readFileSync('src/main.js','utf8'),html=fs.readFileSync('src/widgets/chat/index.html','utf8');
new vm.Script(main);new vm.Script(fs.readFileSync('src/lib/chat-transport.js','utf8'));
let scripts=0;for(const match of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)){new vm.Script(match[1]);scripts++}assert(scripts>0);
function block(s,start,end){const a=s.indexOf(start),b=s.indexOf(end,a+start.length);assert(a>=0&&b>a);return s.slice(a,b)}
const incoming=block(html,'function incoming(m)','function incomingCard');
function renderer(){const alerts=[],c={H:{messages:[],lastReceived:0},save:()=>{},paintChat:()=>{},render:()=>{},log:{},island:true,readUpTo:0,newReply:r=>alerts.push(r.id)};vm.runInNewContext(incoming,c);return {c,alerts}}
const one=renderer(),two=renderer();let failure=true,firstSends=0,secondSends=0,notifications=0,opts;
const c={wins:{one:{isDestroyed:()=>false,webContents:{send:(event,row)=>{assert.equal(event,'chat:msg');firstSends++;one.c.incoming(row)}}},two:{isDestroyed:()=>false,webContents:{send:(event,row)=>{if(failure){failure=false;throw Error('fixture_send_failure')}secondSends++;two.c.incoming(row)}}}},chatCompanions:new Map(),notifyChat:()=>notifications++,require:()=>({createChatTransport:o=>{opts=o;return {start:()=>{},stop:async()=>{}}}}),CHAT_URL:'http://fixture.invalid/chat',CHAT_STREAM_URL:'http://fixture.invalid/chat/stream',CHAT_KEY:'synthetic-fixture',chatStream:{cursor:0,thread:'fixture'},app:{getVersion:()=> 'test',once:()=>{}},broadcastCard:()=>{},broadcastRead:()=>{},bootLog:()=>{}};
vm.runInNewContext(block(main,'const chatDeliverySeen',"ipcMain.handle('chat:stream'"),c);c.runChatStream();
const row={id:'answer',text:'synthetic fixture',received_at:20,from:'agent',in_reply_to:'request'};
assert.throws(()=>opts.onRow(row),/fixture_send_failure/);assert.equal(c.chatStream.cursor,0);assert.equal(notifications,0);assert.equal(one.c.H.messages.length,1);assert.equal(two.c.H.messages.length,0);
opts.onRow(row);assert.equal(c.chatStream.cursor,20);assert.equal(firstSends,2);assert.equal(secondSends,1);assert.equal(one.c.H.messages.length,1);assert.equal(two.c.H.messages.length,1);assert.deepEqual(one.alerts,['answer']);assert.deepEqual(two.alerts,['answer']);assert.equal(notifications,1);
opts.onRow(row);assert.equal(firstSends,2);assert.equal(secondSends,1);assert.equal(notifications,1);
const r=renderer();r.c.incoming({id:'live',text:'fixture',received_at:20,from:'agent'});r.c.incoming({id:'old',text:'fixture',received_at:10,from:'agent'});assert.deepEqual(Array.from(r.c.H.messages,x=>x.id),['old','live']);assert.deepEqual(r.alerts,['live']);
r.c.H.messages.push({id:'user',dir:'out',status:'waiting',at:30});r.c.incoming({id:'user',from:'user',text:'fixture',received_at:40});assert.equal(r.c.H.messages.find(x=>x.id==='user').status,'sent');assert.equal(r.c.H.lastReceived,40);assert.deepEqual(r.alerts,['live']);
r.c.readUpTo=60;r.c.incoming({id:'read',text:'fixture',from:'agent',received_at:50});assert.deepEqual(r.alerts,['live']);
const request={id:'request',dir:'out',status:'sent'},status={H:{messages:[request,{id:'other',dir:'in',in_reply_to:'unrelated'}]}};
vm.runInNewContext(block(html,'function statusText(m)','let toastT='),status);assert.equal(status.statusText(request),'נשמר בשרת');status.H.messages.push({id:'reply',dir:'in',in_reply_to:'request'});assert.equal(status.statusText(request),'נענה');
assert(main.includes("stage:'stored'"));assert(main.includes('השרת מגביל כרגע את קצב ההודעות. נסה שוב מאוחר יותר'));
console.log('PASS candidate hashes, JS parse, partial delivery retry without cursor loss, per-renderer dedupe, stale-history order, optimistic echo, read suppression and exact reply association. No Electron UI or installation.');
