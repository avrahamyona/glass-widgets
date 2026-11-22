'use strict';
const assert=require('node:assert/strict');const {createChatTransport}=require('../src/lib/chat-transport');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn){for(let i=0;i<400;i++){if(fn())return;await delay(2)}throw Error('condition_timeout')}
function harness({onRow=()=>{}}={}){
 const streams=[],requests=[];let rows=[];
 const fetchImpl=async(u,opts)=>{
  requests.push(new URL(u));
  if(new URL(u).pathname==='/chat')return {ok:true,json:async()=>({ok:true,messages:rows})};
  let closed=false,pending=null,queue=[],cancelled=0,released=0;
  const reader={read:()=>queue.length?Promise.resolve(queue.shift()):closed?Promise.resolve({done:true}):new Promise(r=>pending=r),cancel:async()=>{cancelled++;closed=true;if(pending){pending({done:true});pending=null}},releaseLock:()=>{released++}};
  streams.push({send:s=>{const value={done:false,value:Buffer.from(s)};if(pending){const p=pending;pending=null;p(value)}else queue.push(value)},counts:()=>({cancelled,released})});
  // Deliberately does not bind AbortSignal to the reader, as some fetch adapters do.
  return {ok:true,body:{getReader:()=>reader}};
 };
 const c=createChatTransport({getConfig:()=>({url:'http://fixture.invalid/chat',key:'dummy-key'}),fetchImpl,onRow,headerMs:100,idleMs:1000,retryMs:3,maxRetryMs:6});
 return {c,streams,requests,setRows:r=>rows=r};
}
(async()=>{let passed=0;const test=async(n,f)=>{await f();passed++;console.log('ok '+n)};
 await test('stop cancels a pending reader even when adapter ignores AbortSignal',async()=>{const f=harness();f.c.start();await until(()=>f.streams.length===1);await Promise.race([f.c.stop(),delay(200).then(()=>{throw Error('stop_hung')})]);assert(f.streams[0].counts().cancelled>=1);assert.equal(f.streams[0].counts().released,1);const count=f.requests.length;await delay(20);assert.equal(f.requests.length,count)});
 await test('reconnect cancels and releases previous reader before new stream',async()=>{const f=harness();f.c.start();try{await until(()=>f.streams.length===1);f.c.reconnect();await until(()=>f.streams.length===2);assert.equal(f.streams[0].counts().released,1)}finally{await f.c.stop()}});
 await test('CRLF split across chunks and multibyte UTF8 are decoded once',async()=>{const got=[],f=harness({onRow:r=>got.push(r)});f.c.start();try{await until(()=>f.streams.length===1);const s=f.streams[0];s.send('data: {"id":"a","text":"שלום","received_at":10}\r');s.send('\n\r');s.send('\n');await until(()=>got.length===1);assert.equal(got[0].text,'שלום');const bytes=Buffer.from('data: {"id":"utf8","text":"שלום","received_at":11}\n\n');const split=bytes.indexOf(Buffer.from('ש'))+1;s.send(bytes.subarray(0,split));s.send(bytes.subarray(split));await until(()=>got.length===2);assert.equal(got[1].text,'שלום');s.send('data: {"id":"a","text":"duplicate","received_at":10}\n\n');await delay(10);assert.equal(got.length,2)}finally{await f.c.stop()}});
 await test('delivery callback failure does not consume live cursor, history recovers row',async()=>{let first=true;const got=[],row={id:'retry-row',text:'fixture',received_at:100};const f=harness({onRow:r=>{if(first){first=false;throw Error('delivery_failed')}got.push(r)}});f.c.start();try{await until(()=>f.streams.length===1);f.setRows([row]);f.streams[0].send('data: '+JSON.stringify(row)+'\n\n');await until(()=>got.length===1);assert.equal(got[0].id,row.id);assert.equal(f.c.state().historyCursor,100);assert(f.streams[0].counts().released===1)}finally{await f.c.stop()}});
 await test('new live row never changes history reconnect cursor',async()=>{const got=[],f=harness({onRow:r=>got.push(r)});f.c.start();try{await until(()=>f.streams.length===1);f.streams[0].send('data: {"id":"new","text":"fixture","received_at":500}\n\n');await until(()=>got.length===1);assert.equal(f.c.state().historyCursor,0);f.c.reconnect();await until(()=>f.streams.length===2);const histories=f.requests.filter(u=>u.pathname==='/chat');assert.equal(histories.at(-1).searchParams.get('after'),'0');const live=f.requests.filter(u=>u.pathname==='/chat/stream');assert.equal(live.at(-1).searchParams.get('after'),'499')}finally{await f.c.stop()}});
 console.log(passed+' chat transport recovery tests passed; fake network only');
})().catch(e=>{console.error(e);process.exitCode=1});
