// Chat-only LAN listener (0.4.65): exposes the /chat routes with the chat token on the LAN and
// NOTHING else - the command API (run_command, files, reads) must never exist on this listener.
const{createChatLan}=require('../server/lib/chat-lan');
const{createChat}=require('../server/lib/chat');
const fs=require('fs'),os=require('os'),path=require('path');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const CHAT='chat-key-lan';

async function main(){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gwchatlan-'));
 const chat=createChat({dir,log:()=>{}});
 const logs=[];
 const r=await createChatLan({port:0,host:'127.0.0.1',token:CHAT,handle:(req,res,reply)=>chat.handle(req,res,reply),log:(l,o)=>logs.push({l,...o})});
 assert(r.started,'lan listener started');
 const U='http://127.0.0.1:'+r.port;
 const J=async(p,opts)=>{const res=await fetch(U+p,opts);let body=null;try{body=await res.json()}catch{}return{status:res.status,body}};

 // 1) auth: no key / wrong key -> 403; right key (query or header) -> 200
 assert((await J('/chat')).status===403,'no key -> 403');
 assert((await J('/chat?key=nope')).status===403,'wrong key -> 403');
 assert((await J('/chat?key='+CHAT)).status===200,'query key ok');
 assert((await J('/chat',{headers:{'x-gw-chat-key':CHAT}})).status===200,'header key ok');
 assert(logs.some(l=>l.stage==='auth_fail'),'auth failure audited');

 // 2) chat-only surface: no command, health, info or file routes on this listener - even with keys
 for(const p of ['/health','/info','/command','/file?p=x','/chatx']){
  assert((await J(p,{headers:{'x-gw-chat-key':CHAT,'x-gw-key':'cmd-key-1'}})).status===404,'non-chat route 404: '+p);
 }
 assert(logs.some(l=>l.stage==='not_chat_route'),'non-chat access audited');

 // 3) send + history through the LAN listener land in the SAME store (the shared-chat contract)
 const s1=await J('/chat?key='+CHAT,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:'lan1',text:'מהלפטופ',at:1})});
 assert(s1.status===200&&s1.body.ok,'send ok: '+JSON.stringify(s1.body));
 const h=await J('/chat?key='+CHAT+'&after=0');
 assert(h.body.messages.length===1&&h.body.messages[0].id==='lan1'&&h.body.messages[0].from==='user','row stored as user: '+JSON.stringify(h.body.messages));

 r.close();
 console.log('server-chat-lan-unit OK');
}
main().catch(e=>{console.error('FAIL:',e);process.exit(1)});
