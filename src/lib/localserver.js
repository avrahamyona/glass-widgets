// Embedded localhost HTTP server: the "own server" leg (Efi's model - server on his PC, exposed by
// an outbound tunnel; no VPS, no open ports). cloudflared proxies https://<tunnel> to this listener.
// Electron-free by design so tests/agent-server-unit.js can run it directly.
// Auth: every request must carry the agent command key (X-GW-Key); the listener binds to
// 127.0.0.1 only, so it is unreachable from the LAN - the tunnel is the only way in.
const http=require('http');

const BODY_CAP=256*1024; // generous vs the worker envelope (4000) - the point of the own server; still bounded so a broken client cannot exhaust memory

function startLocalServer({port,token,version,caps,onCommand,log,deviceId,deviceSign}){
 if(!token)return {started:false,reason:'no-token'};
 const say=(lvl,obj)=>{try{if(log)log(lvl,obj)}catch{}};
 const server=http.createServer((req,res)=>{
  const reply=(code,obj)=>{const s=JSON.stringify(obj);res.writeHead(code,{'content-type':'application/json','content-length':Buffer.byteLength(s)});res.end(s)};
  if(req.headers['x-gw-key']!==token){say('warn',{kind:'server',stage:'auth_fail',method:req.method,url:String(req.url).slice(0,60)});return reply(403,{ok:false,error:'auth'})}
  if(req.method==='GET'&&req.url.startsWith('/health')){
   // sender-side identity proof: with ?nonce= the server signs deviceId+nonce with the per-device
   // key, so the sender verifies the endpoint holds the enrolled device key BEFORE any payload.
   const body={ok:true,v:version||'',caps:caps||''};
   if(deviceId&&deviceSign){const nonce=(req.url.split('nonce=')[1]||'').split('&')[0];
    if(/^[A-Za-z0-9_-]{8,64}$/.test(nonce)){try{body.deviceId=deviceId;body.sig=deviceSign(nonce)}catch{}}}
   return reply(200,body)}
  if(req.method==='POST'&&req.url==='/cmd'){
   let n=0,chunks=[];
   req.on('data',c=>{n+=c.length;if(n>BODY_CAP){say('warn',{kind:'server',stage:'body_cap',bytes:n});reply(413,{ok:false,error:'too_large'});req.destroy()}else chunks.push(c)});
   req.on('end',()=>{
    if(n>BODY_CAP)return; // already answered
    let m=null;
    try{m=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{return reply(400,{ok:false,error:'bad_json'})}
    if(!m||typeof m!=='object'||typeof m.kind!=='string'||typeof m.id!=='string')return reply(400,{ok:false,error:'bad_command'});
    let accepted=true,reason='',status=0;
    try{const r=onCommand(m);if(r&&r.accepted===false){accepted=false;reason=String(r.reason||'refused').slice(0,120);status=+r.status||0}}catch(e){accepted=false;reason='handler_error';status=500}
    say('info',{kind:'server',stage:'cmd',id:m.id.slice(0,40),kind:m.kind.slice(0,40),accepted,reason});
    reply(accepted?202:(status>=400&&status<600?status:409),{ok:accepted,...(reason?{reason}:{})});
   });
   req.on('error',()=>{});
   return;
  }
  reply(404,{ok:false,error:'not_found'});
 });
 return new Promise(resolve=>{
  server.on('error',e=>{say('warn',{kind:'server',stage:'listen_fail',err:String(e&&e.code||e)});resolve({started:false,reason:String(e&&e.code||e)})});
  server.listen(port,'127.0.0.1',()=>{const bound=server.address().port;say('info',{kind:'server',stage:'listening',port:bound});resolve({started:true,port:bound,stop:()=>new Promise(r=>server.close(r))})});
 });
}
module.exports={startLocalServer,BODY_CAP};
