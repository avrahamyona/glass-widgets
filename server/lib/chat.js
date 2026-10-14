// Local chat store + SSE hub for the island ("own chat server" leg - replaces the external
// fixes-center worker). Messages live in <dir>/chat-log.json, screenshots in <dir>/shots/.
// No accounts, no external calls, no quotas beyond a light local flood guard.
// Response shapes deliberately mirror the old worker's so the island client barely changes:
//   POST /chat          {key,id,text,at,in_reply_to,from?} -> {ok:true,id,duplicate?}
//   GET  /chat?key&after&limit                            -> {ok:true,messages[],cards:[],read_upto:0}
//   GET  /chat/stream?key&after                           -> SSE rows, one JSON per data: line
//   POST /chat/screenshot {key,id,image(base64),at}        -> {ok:true,id} + a chat row with file ref
const fs=require('fs'),path=require('path'),crypto=require('crypto');

const CAP=2000;              // messages retained on disk
const SEND_WINDOW_MS=60e3, SEND_MAX=120; // light local flood guard (per process)
const SHOT_MAX=4000000;      // decoded bytes, mirrors the old client-side cap

function createChat({dir,log}){
 const file=path.join(dir,'chat-log.json');
 const shotsDir=path.join(dir,'shots');
 let rows=[];
 const clients=new Set();
 const sentAt=[];
 const say=(lvl,o)=>{try{if(log)log(lvl,o)}catch{}};

 try{const j=JSON.parse(fs.readFileSync(file,'utf8'));if(Array.isArray(j.rows))rows=j.rows.filter(r=>r&&typeof r.text==='string')}catch{}
 function save(){
  const tmp=file+'.tmp-'+process.pid;
  try{fs.writeFileSync(tmp,JSON.stringify({rows:rows.slice(-CAP)}));fs.renameSync(tmp,file)}catch(e){say('warn',{kind:'chat',stage:'save_fail',err:String(e&&e.code||e)})}
 }
 function broadcast(row){
  const line='data: '+JSON.stringify(row)+'\n\n';
  for(const res of clients){try{res.write(line)}catch{clients.delete(res)}}
 }
 function send(o,from){
  const now=Date.now();while(sentAt.length&&sentAt[0]<now-SEND_WINDOW_MS)sentAt.shift();
  if(sentAt.length>=SEND_MAX)return{ok:false,status:429,error:'חריגה מהמכסה המקומית - נסה שוב בעוד דקה'};
  const text=String(o&&o.text||'').slice(0,4000);
  if(!text.trim())return{ok:false,status:400,error:'text_too_short'};
  const id=String(o.id||crypto.randomUUID()).slice(0,80);
  const dup=rows.find(r=>r.id===id);
  if(dup)return{ok:true,id:dup.id,duplicate:true};
  sentAt.push(now);
  const row={id,text,at:+o.at||now,received_at:now,in_reply_to:String(o.in_reply_to||'').slice(0,80),from:String(from||'user').slice(0,20)};
  rows.push(row);if(rows.length>CAP*2)rows=rows.slice(-CAP);
  save();broadcast(row);
  return{ok:true,id:row.id};
 }
 function history(after,limit){
  after=+after||0;limit=Math.min(200,Math.max(1,+limit||50));
  return rows.filter(r=>r.received_at>after).sort((a,b)=>a.received_at-b.received_at).slice(0,limit);
 }
 function stream(req,res,after){
  res.writeHead(200,{'content-type':'text/event-stream','cache-control':'no-cache','connection':'keep-alive'});
  res.write(': ok\n\n');
  for(const r of history(after,50)){try{res.write('data: '+JSON.stringify(r)+'\n\n')}catch{}}
  clients.add(res);
  const hb=setInterval(()=>{try{res.write(': hb\n\n')}catch{}},25000);
  req.on('close',()=>{clearInterval(hb);clients.delete(res)});
 }
 function storeShot(o){
  const id=String(o&&o.id||crypto.randomUUID()).slice(0,80);
  let buf=null;try{buf=Buffer.from(String(o&&o.image||''),'base64')}catch{}
  if(!buf||!buf.length)return{ok:false,status:400,error:'bad_image'};
  if(buf.length>SHOT_MAX)return{ok:false,status:413,error:'התמונה גדולה מדי'};
  try{fs.mkdirSync(shotsDir,{recursive:true});fs.writeFileSync(path.join(shotsDir,id+'.jpg'),buf)}catch(e){return{ok:false,status:500,error:'save_failed'}}
  if(!rows.some(r=>r.id===id)){
   const row={id,text:'📷 צילום מסך',at:+o.at||Date.now(),received_at:Date.now(),in_reply_to:'',from:'user',
    file:{name:id+'.jpg',size:buf.length,mime:'image/jpeg',path:path.join(shotsDir,id+'.jpg')}};
   rows.push(row);save();broadcast(row);
  }
  return{ok:true,id};
 }
 function importOnce(importDirs){ // one-time import of the island's existing chat-*.json history
  const marker=file+'.imported';
  try{fs.statSync(marker);return{imported:0,skipped:true}}catch{}
  let n=0;const seen=new Set(rows.map(r=>r.id));
  for(const d of importDirs||[]){
   let names=[];try{names=fs.readdirSync(d)}catch{continue}
   for(const nm of names){
    if(!/^chat-.+\.json$/.test(nm))continue;
    let h=null;try{h=JSON.parse(fs.readFileSync(path.join(d,nm),'utf8'))}catch{continue}
    if(!h||!Array.isArray(h.messages))continue;
    for(const m of h.messages){
     if(!m||typeof m.text!=='string'||!m.id||seen.has(m.id)||m.status==='waiting')continue;
     seen.add(m.id);n++;
     rows.push({id:String(m.id).slice(0,80),text:String(m.text).slice(0,4000),at:+m.at||0,
      received_at:+m.received_at||+m.at||n,in_reply_to:String(m.in_reply_to||'').slice(0,80),from:m.dir==='in'?'agent':'user'});
    }
   }
  }
  if(n){rows.sort((a,b)=>(a.received_at||a.at)-(b.received_at||b.at));save()}
  try{fs.writeFileSync(marker,new Date().toISOString()+' imported='+n+'\n')}catch{}
  return{imported:n};
 }

 // HTTP routing under /chat - called by localserver AFTER the chat-token check.
 // reply(code,obj) is the localserver's JSON responder.
 function handle(req,res,reply){
  const u0=req.url.split('?')[0],q=req.url.split('?')[1]||'';
  const qp={};for(const part of q.split('&')){const i=part.indexOf('=');qp[decodeURIComponent(i===-1?part:part.slice(0,i))]=decodeURIComponent(i===-1?'':part.slice(i+1))}
  if(req.method==='GET'&&u0==='/chat')return reply(200,{ok:true,messages:history(qp.after,qp.limit),cards:[],read_upto:0});
  if(req.method==='GET'&&u0==='/chat/stream')return stream(req,res,qp.after);
  if(req.method==='POST'&&(u0==='/chat'||u0==='/chat/screenshot')){
   let n=0,chunks=[];
   req.on('data',c=>{n+=c.length;if(n>SHOT_MAX+65536){reply(413,{ok:false,error:'too_large'});req.destroy()}else chunks.push(c)});
   req.on('end',()=>{
    if(n>SHOT_MAX+65536)return;
    let m=null;try{m=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{return reply(400,{ok:false,error:'bad_json'})}
    const out=u0==='/chat/screenshot'?storeShot(m):send(m,m&&m.from==='agent'?'agent':'user');
    return reply(out.ok?200:(out.status||500),out);
   });
   req.on('error',()=>{});
   return;
  }
  return reply(404,{ok:false,error:'not_found'});
 }
 return{send,history,stream,storeShot,importOnce,handle,count:()=>rows.length};
}
module.exports={createChat,CAP,SHOT_MAX};
