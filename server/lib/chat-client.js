// Responder-side client for the island's local chat ("חיים" replies). Reaches the PC's own
// server through whatever base URL is current - the rotating trycloudflare URL (from the
// pointer mail) or plain loopback on the PC. Chat-token scoped: reads and posts CHAT ONLY;
// this token opens no command, file, or task routes on the server.
// Usage:
//   const cc=require('./chat-client');
//   await cc.send(base, token, 'שלום!', {from:'agent'});
//   const {messages}=await cc.history(base, token, after);
//   await cc.stream(base, token, after, {onRow:m=>..., signal:ctl.signal});
function keyed(base,token){return base+(base.includes('?')?'&':'?')+'key='+encodeURIComponent(token)}

async function send(base,token,text,{id,inReplyTo,from}={}){
 const body={key:String(token),id:String(id||crypto.randomUUID()),text:String(text||''),at:Date.now(),in_reply_to:String(inReplyTo||''),from:String(from||'agent')};
 const r=await fetch(keyed(base,token),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
 const j=await r.json().catch(()=>({}));
 return {status:r.status,...j};
}
async function history(base,token,after,limit){
 const u=new URL(keyed(base,token));if(after)u.searchParams.set('after',String(after));if(limit)u.searchParams.set('limit',String(limit));
 const r=await fetch(u,{signal:AbortSignal.timeout(20000)});
 return {status:r.status,...(await r.json().catch(()=>({})))};
}
async function stream(base,token,after,{onRow,signal}){
 const su=new URL(base.replace(/\/chat$/,'/chat/stream'));su.searchParams.set('key',token);if(after)su.searchParams.set('after',String(after));
 const r=await fetch(su,{signal,headers:{accept:'text/event-stream'}});
 if(!r.ok||!r.body)return {status:r.status,ok:false};
 const reader=r.body.getReader(),dec=new TextDecoder();let buf='';
 while(true){
  const{done,value}=await reader.read();if(done)return {ok:true,closed:true};
  buf+=dec.decode(value,{stream:true});
  let i;while((i=buf.indexOf('\n\n'))>=0){const chunk=buf.slice(0,i);buf=buf.slice(i+2);
   const line=chunk.split('\n').find(l=>l.startsWith('data:'));if(!line)continue;
   try{const m=JSON.parse(line.slice(5).trim());if(m&&typeof m.text==='string')onRow&&onRow(m)}catch{}}
 }
}
module.exports={send,history,stream};
