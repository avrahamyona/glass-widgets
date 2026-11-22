'use strict';
const assert=require('node:assert/strict'),http=require('node:http');
const {createChatTransport}=require('../src/lib/chat-transport');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,timeout=2000){const end=Date.now()+timeout;while(!fn()){if(Date.now()>end)throw Error('condition_timeout');await delay(5)}}
(async()=>{
 let streams=new Set(),requests=[],historyMode='stall',historyRows=[],historyReads=0;
 const server=http.createServer((req,res)=>{const u=new URL(req.url,'http://localhost');requests.push(u);
  if(u.searchParams.get('key')!=='fixture-secret'){res.writeHead(403);res.end('{}');return}
  if(u.pathname==='/chat/stream'){res.writeHead(200,{'content-type':'text/event-stream'});res.write(': ready\r\n\r\n');streams.add(res);res.on('close',()=>streams.delete(res));return}
  if(u.pathname==='/chat'){historyReads++;if(historyMode==='stall'){req.on('close',()=>res.destroy());return}
   res.setHeader('content-type','application/json');res.end(JSON.stringify({ok:true,messages:historyRows.filter(r=>r.received_at>Number(u.searchParams.get('after'))).slice(0,Number(u.searchParams.get('limit')))}));return}
  res.writeHead(404);res.end();
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
 let config={url:base+'/chat',key:'fixture-secret'},got=[],metrics=[];
 const c=createChatTransport({getConfig:()=>config,onRow:r=>got.push(r),onMetric:m=>metrics.push(m),headerMs:120,idleMs:1500,retryMs:15,maxRetryMs:30,pageSize:3,maxPages:10});
 const start=c.start();assert.equal(c.start(),start,'one stream loop even if many windows call start');
 try{
  await until(()=>streams.size===1&&historyReads===1);
  const write=o=>{for(const s of streams)s.write('data: '+JSON.stringify(o)+'\r\n\r\n')};
  const r2={id:'new',text:'new reply',received_at:20,from:'agent',in_reply_to:'request'};
  write(r2);await until(()=>got.length===1);assert.equal(got[0].id,'new','live event delivered while history is stalled');
  assert.equal(c.state().historyCursor,0,'live receipt cannot skip missing history');
  write(r2);await delay(15);assert.equal(got.length,1,'duplicate stream event not repeated');
  await until(()=>metrics.some(m=>m.stage==='history_retry_needed'));
  historyMode='ok';historyRows=[{id:'old',text:'missed',received_at:10},r2,{id:'third',text:'third',received_at:30},{id:'fourth',text:'fourth',received_at:40}];
  const established=requests.filter(u=>u.pathname==='/chat/stream').length;
  await until(()=>got.length===4);assert.equal(requests.filter(u=>u.pathname==='/chat/stream').length,established,'history retries without reconnecting live stream');assert.deepEqual(got.map(r=>r.id).sort(),['fourth','new','old','third']);assert.equal(c.state().historyCursor,40,'paginated catchup reaches all records despite newer live receipt');
  assert(!JSON.stringify(metrics).includes('fixture-secret'));assert(!JSON.stringify(metrics).includes('new reply'),'metrics omit auth and message body');
  for(const stream of streams){stream.write('data: null\n\ndata: {broken}\n\ndata: {\n');stream.write('data: \"id\":\"multiline\",\"text\":\"fixture\",\"received_at\":50}\n\n')}
  await until(()=>got.some(r=>r.id==='multiline'));assert(metrics.some(m=>m.stage==='invalid_frame'));
  const oldStreams=requests.filter(u=>u.pathname==='/chat/stream').length;await until(()=>requests.filter(u=>u.pathname==='/chat/stream').length>oldStreams,2500);
  const before=requests.length;config={url:base+'/rotated/chat',streamUrl:base+'/alternate-stream',key:'fixture-secret',thread:'fixture-thread',version:'test-version'};c.reconnect();await until(()=>requests.length>before&&requests.some(u=>u.pathname==='/alternate-stream'&&u.searchParams.get('thread')==='fixture-thread'&&u.searchParams.get('v')==='test-version'));config={url:base+'/chat',key:'fixture-secret'};c.reconnect();
  await c.stop();await until(()=>streams.size===0);const stopped=requests.length;await delay(80);assert.equal(requests.length,stopped,'stop clears reconnect work');
  console.log('chat-transport-unit PASS: headless singleton, live-first stalled catchup, dedupe, pagination, retry, refreshed configuration, clean shutdown, private metrics');
 }finally{await c.stop();for(const s of streams)s.destroy();server.closeAllConnections();await new Promise(r=>server.close(r))}
 // Invalid/missing config never sends an arbitrary request.
 let calls=0;const invalid=createChatTransport({getConfig:()=>({url:'file:///secret',key:'x'}),onRow:()=>{},fetchImpl:async()=>{calls++;throw Error('unexpected')},retryMs:5});invalid.start();await delay(15);await invalid.stop();assert.equal(calls,0);
})().catch(e=>{console.error(e);process.exitCode=1});
