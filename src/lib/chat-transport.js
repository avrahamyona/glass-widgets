'use strict';
// Desktop chat transport only. No model execution, file access, or remote wake service.
// Auth is supplied by the existing local provisioning reader, never logged here.
function createChatTransport({getConfig,onRow,onCard=()=>{},onRead=()=>{},onMetric=()=>{},fetchImpl=fetch,headerMs=8000,idleMs=60000,retryMs=1000,maxRetryMs=5000,pageSize=50,maxPages=50,seenLimit=4096,now=Date.now}){
 let running=false,task=null,session=null,wakeDelay=null,urgent=false,historyCursor=0,liveCursor=0;
 const seen=new Map();
 const metric=(stage,start,extra={})=>{try{onMetric({stage,at:now(),elapsed_ms:Math.max(0,now()-start),...extra})}catch{}};
 const emit=row=>{if(!row||typeof row.text!=='string'||typeof row.id!=='string'||!row.id)return;
  if(seen.has(row.id))return;
  onRow(row); // If delivery throws, do not consume the cursor or mark it seen.
  seen.set(row.id,true);if(seen.size>seenLimit)seen.delete(seen.keys().next().value);
  liveCursor=Math.max(liveCursor,+row.received_at||0);
 };
 function config(){const c=getConfig();if(!c||!c.url||!c.key)throw Error('not_provisioned');
  const u=new URL(c.url);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error('invalid_configuration');
  const stream=c.streamUrl?new URL(c.streamUrl):new URL(u);if(!c.streamUrl)stream.pathname=stream.pathname.replace(/\/chat\/?$/,'/chat/stream');
  if(!['http:','https:'].includes(stream.protocol)||stream.username||stream.password)throw Error('invalid_configuration');
  return {url:u.toString(),streamUrl:stream.toString(),key:String(c.key),thread:c.thread,version:c.version};
 }
 function url(c,stream,after){const u=new URL(stream?c.streamUrl:c.url);if(c.thread)u.searchParams.set('thread',String(c.thread));if(c.version)u.searchParams.set('v',String(c.version));
  u.searchParams.set('key',c.key);u.searchParams.set('after',String(after));if(!stream)u.searchParams.set('limit',String(pageSize));return u;
 }
 async function catchup(c,s){const start=now();let cursor=historyCursor;
  for(let p=0;p<maxPages&&!s.ctl.signal.aborted;p++){
   const ctl=new AbortController(),abort=()=>ctl.abort();s.ctl.signal.addEventListener('abort',abort,{once:true});
   const timer=setTimeout(abort,headerMs);let j;
   try{const r=await fetchImpl(url(c,false,Math.max(0,cursor-1)),{signal:ctl.signal,redirect:'error'});if(!r.ok)throw Error('history_status');j=await r.json()}
   finally{clearTimeout(timer);s.ctl.signal.removeEventListener('abort',abort)}
   if(s.ctl.signal.aborted)return;
   if(!j||j.ok!==true||!Array.isArray(j.messages))throw Error('history_shape');
   const rows=j.messages;let next=cursor;
   for(const row of rows){emit(row);next=Math.max(next,+row.received_at||0)}
   for(const card of j.cards||[])onCard(card);if(+j.read_upto>0)onRead(+j.read_upto);
   // Advance only from a successful history page, NEVER from a newer live row.
   historyCursor=next;
   if(rows.length<pageSize){metric('history_caught_up',start,{pages:p+1});return}
   if(next<=cursor)throw Error('history_cursor_stalled');cursor=next;
  }
  if(!s.ctl.signal.aborted)throw Error('history_page_limit');
 }
 async function recoverHistory(c,s){let backoff=retryMs;
  while(!s.ctl.signal.aborted){try{await catchup(c,s);return}catch{metric('history_retry_needed',now())}
   await new Promise(resolve=>{const finish=()=>{clearTimeout(t);s.ctl.signal.removeEventListener('abort',finish);resolve()};const t=setTimeout(finish,backoff);s.ctl.signal.addEventListener('abort',finish,{once:true});if(s.ctl.signal.aborted)finish()});backoff=Math.min(maxRetryMs,backoff*2);
  }
 }
 async function connect(c,s){const start=now();let timer=setTimeout(()=>s.ctl.abort(),headerMs),reader=null;
  const cancelReader=()=>{if(reader)Promise.resolve(reader.cancel()).catch(()=>{})};
  s.ctl.signal.addEventListener('abort',cancelReader,{once:true});
  try{const connecting=fetchImpl(url(c,true,Math.max(0,liveCursor-1)),{signal:s.ctl.signal,redirect:'error',headers:{accept:'text/event-stream'}});
   s.catchup=recoverHistory(c,s); // begin independently, including while stream headers stall
   const r=await connecting;
   clearTimeout(timer);if(!r.ok||!r.body)throw Error('stream_status');
   const poke=()=>{clearTimeout(timer);timer=setTimeout(()=>s.ctl.abort(),idleMs)};poke();metric('stream_connected',start);
   // A slow history request cannot delay establishing or reading the live stream.
   reader=r.body.getReader();const decoder=new TextDecoder();let pending='';
   if(s.ctl.signal.aborted)cancelReader();
   while(!s.ctl.signal.aborted){const {done,value}=await reader.read();if(done)throw Error('stream_closed');poke();pending+=decoder.decode(value,{stream:true});
    if(pending.length>1024*1024)throw Error('stream_frame_limit');
    // CRLF and LF SSE frames, multiline data, comments/heartbeats ignored.
    pending=pending.replace(/\r\n/g,'\n');let end;
    while((end=pending.indexOf('\n\n'))!==-1){const frame=pending.slice(0,end);pending=pending.slice(end+2);
     const data=frame.split('\n').filter(x=>x.startsWith('data:')).map(x=>x.slice(5).replace(/^ /,'')).join('\n');if(!data)continue;
     let row;try{row=JSON.parse(data)}catch{metric('invalid_frame',start);continue}
     if(!row||typeof row!=='object')continue;
     if(row.type==='read')onRead(row.upto);else if(row.type==='card'&&row.card)onCard(row.card);else emit(row);
    }
   }
  }finally{clearTimeout(timer);s.ctl.abort();s.ctl.signal.removeEventListener('abort',cancelReader);if(reader){try{await reader.cancel()}catch{}try{reader.releaseLock()}catch{}}if(s.catchup)await s.catchup}
 }
 async function loop(){let backoff=retryMs;while(running){const s={ctl:new AbortController()};session=s;
   try{await connect(config(),s)}catch{metric('connection_retry',now())}finally{s.ctl.abort();session=null}
   if(!running)break;if(urgent){urgent=false;backoff=retryMs;continue}
   await new Promise(resolve=>{const t=setTimeout(resolve,backoff);wakeDelay=()=>{clearTimeout(t);resolve()}});wakeDelay=null;backoff=Math.min(maxRetryMs,backoff*2);
  }}
 return {
  start(after=0){if(running)return task;historyCursor=Math.max(historyCursor,+after||0);liveCursor=Math.max(liveCursor,historyCursor);running=true;task=loop();return task},
  reconnect(){if(!running)return;urgent=true;if(session)session.ctl.abort();if(wakeDelay)wakeDelay()},
  async stop(){running=false;if(session)session.ctl.abort();if(wakeDelay)wakeDelay();await task},
  state(){return {running,historyCursor,liveCursor,seen:seen.size}}
 };
}
module.exports={createChatTransport};
