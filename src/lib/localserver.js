// Embedded localhost HTTP server: the "own server" leg (Efi's model - server on his PC, exposed by
// an outbound tunnel; no VPS, no open ports). cloudflared proxies https://<tunnel> to this listener.
// Electron-free by design so tests/agent-server-unit.js can run it directly.
// Auth: every request must carry the agent command key (X-GW-Key); the listener binds to
// 127.0.0.1 only, so it is unreachable from the LAN - the tunnel is the only way in.
const http=require('http'),crypto=require('crypto');

const BODY_CAP=256*1024; // generous vs the worker envelope (4000) - the point of the own server; still bounded so a broken client cannot exhaust memory

function startLocalServer({port,token,version,caps,onCommand,log,getDevice,getTask,tasksOk,getInfo,verifyReadAuth}){
 if(!token)return {started:false,reason:'no-token'};
 const say=(lvl,obj)=>{try{if(log)log(lvl,obj)}catch{}};
 const server=http.createServer((req,res)=>{
  // device-signed responses: the signature binds the RESPONSE to the REQUEST - deviceId, method,
  // path, query, the request's read ts+nonce, the HTTP status and the sha256 of the exact body -
  // so a signed body can never be replayed onto another request, endpoint or nonce. Errors are
  // signed too (whenever a device key exists).
  const reply=(code,obj,sign)=>{
   const s=JSON.stringify(obj);const h={'content-type':'application/json','content-length':Buffer.byteLength(s)};
   if(sign){const d=getDevice&&getDevice();
    if(d&&d.deviceId&&d.deviceSign){try{
     const bh=crypto.createHash('sha256').update(s,'utf8').digest('hex');
     h['x-gw-device']=d.deviceId;
     h['x-gw-device-sig']=String(d.deviceSign([d.deviceId,req.method,req.url.split('?')[0],(req.url.split('?')[1]||''),String(req.headers['x-gw-read-ts']||''),String(req.headers['x-gw-read-nonce']||''),String(code),bh].join('\n'))).replace(/[\r\n]/g,''); // hex in production; single-line enforced for header safety
    }catch{}}}
   res.writeHead(code,h);res.end(s)};
  // private-read gate for /task and /info: the baked key is public; reads need the worker-signed
  // request-bound proof (verifyReadAuth) ON TOP of it.
  const readOk=()=>{
   if(!verifyReadAuth){say('warn',{kind:'server',stage:'read_auth_fail',method:req.method,url:String(req.url).slice(0,60),reason:'no_verifier'});return false}
   const q=(req.url.split('?')[1]||'');
   const ok=verifyReadAuth(req.method,req.url.split('?')[0],q,req.headers);
   if(!ok)say('warn',{kind:'server',stage:'read_auth_fail',method:req.method,url:String(req.url).slice(0,60)});
   return ok};
  if(req.headers['x-gw-key']!==token){say('warn',{kind:'server',stage:'auth_fail',method:req.method,url:String(req.url).slice(0,60)});return reply(403,{ok:false,error:'auth'})}
  if(req.method==='GET'&&req.url.startsWith('/health')){
   // sender-side identity proof: with ?nonce= the server signs deviceId+nonce with the per-device
   // key, so the sender verifies the endpoint holds the enrolled device key BEFORE any payload.
   const body={ok:true,v:version||'',caps:caps||''};
   const d=getDevice&&getDevice(); // resolved per request: enrollment must not need a server restart
   if(d&&d.deviceId&&d.deviceSign){const nonce=(req.url.split('nonce=')[1]||'').split('&')[0];
    if(/^[A-Za-z0-9_-]{8,64}$/.test(nonce)){try{body.deviceId=d.deviceId;body.sig=d.deviceSign(d.deviceId+'\n'+nonce)}catch{}}}
   return reply(200,body)}
  if(req.method==='GET'&&req.url.split('?')[0]==='/info'){
   // self-description for the sender: version, capabilities, device identity (pubkey is public
   // by nature). PRIVATE READ: signed-read auth required; device-signed response when enrolled.
   if(!readOk())return reply(403,{ok:false,error:'read_auth'},true);
   const base={ok:true,v:version||'',caps:caps||''};
   const info=getInfo?getInfo():null;
   const body=info&&typeof info==='object'?{...base,...info}:{...base,deviceless:true};
   return reply(200,body,true)}
  if(req.method==='GET'&&req.url.split('?')[0]==='/task'){
   // idempotent task-result polling: accepted at intake, terminal at ack. Results are PRIVATE
   // (paths, clipboard, command output): signed-read auth AND an enrolled device key (the
   // response is device-signed; without a key the endpoint is closed). Unknown id -> 404;
   // a broken ledger -> 503 (fail-closed, never a pretend answer).
   if(!readOk())return reply(403,{ok:false,error:'read_auth'},true);
   const d=getDevice&&getDevice();
   if(!d||!d.deviceId||!d.deviceSign)return reply(503,{ok:false,error:'no_device_key'},true);
   if(tasksOk&&!tasksOk())return reply(503,{ok:false,error:'ledger'},true);
   const id=(req.url.split('id=')[1]||'').split('&')[0];
   const t=id&&getTask?getTask(id):null;
   if(!t)return reply(404,{ok:false,error:'unknown_task'},true);
   return reply(200,{ok:true,id,status:t.status,note:t.note,result:t.result,at:t.at,terminal:!!t.terminal},true)}
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
