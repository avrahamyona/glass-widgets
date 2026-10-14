// Chat-only LAN listener (two-machine island chat, 0.4.65): a second HTTP server that exposes
// ONLY the /chat routes on the local network, so a second machine's island (laptop) shares the
// same chat store. The command API stays bound to loopback - run_command never leaves
// 127.0.0.1. Same chat-token check as the embedded localserver route (timing-safe compare,
// header x-gw-chat-key or ?key= query), then the same chat module handler.
// Opt-in only: server/index.js starts this when GW_CHAT_LAN=1 or cfg.chatLan===true.
const http=require('http'),crypto=require('crypto');

function createChatLan({port,host,token,handle,log}){
 const say=(lvl,o)=>{try{if(log)log(lvl,o)}catch{}};
 const server=http.createServer((req,res)=>{
  const reply=(code,obj)=>{try{res.writeHead(code,{'content-type':'application/json'});res.end(JSON.stringify(obj))}catch{}};
  const u0=String(req.url||'').split('?')[0];
  if(u0!=='/chat'&&!u0.startsWith('/chat/')){say('warn',{kind:'chat_lan',stage:'not_chat_route',method:req.method,url:u0.slice(0,60)});return reply(404,{ok:false,error:'not_found'})}
  const q0=String(req.url||'').split('?')[1]||'';
  let k=String(req.headers['x-gw-chat-key']||'');
  if(!k)for(const part of q0.split('&')){const i=part.indexOf('=');if(part.slice(0,i===-1?part.length:i)==='key'){k=decodeURIComponent(i===-1?'':part.slice(i+1));break}}
  const ab=Buffer.from(k),bb=Buffer.from(String(token));
  if(ab.length!==bb.length||!crypto.timingSafeEqual(ab,bb)){say('warn',{kind:'chat_lan',stage:'auth_fail',method:req.method,url:u0.slice(0,60)});return reply(403,{ok:false,error:'auth'})}
  return handle(req,res,reply);
 });
 return new Promise(resolve=>{
  const onErr=e=>resolve({started:false,reason:String(e&&e.code||e)});
  server.once('error',onErr);
  server.listen(port,host,()=>{
   server.removeListener('error',onErr);
   const a=server.address();
   resolve({started:true,port:a&&a.port,close:()=>{try{server.close()}catch{}}});
  });
 });
}
module.exports={createChatLan};
