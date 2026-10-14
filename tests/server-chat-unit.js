// Local chat routes on the own-server: auth, send/dedupe, history cursor, SSE stream,
// screenshot storage, history import. Electron-free: drives startLocalServer + chat module.
const{startLocalServer}=require('../src/lib/localserver');
const{createChat}=require('../server/lib/chat');
const fs=require('fs'),os=require('os'),path=require('path');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const TOKEN='cmd-key-1',CHAT='chat-key-1';

async function main(){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gwchat-'));
 const chat=createChat({dir,log:()=>{}});
 const logs=[];
 const r=await startLocalServer({port:0,token:TOKEN,version:'t',caps:'chat',log:(l,o)=>logs.push({l,...o}),
  onCommand:()=>({accepted:true}),chat:{token:CHAT,handle:(req,res,reply)=>chat.handle(req,res,reply)}});
 assert(r.started,'server started');
 const U='http://127.0.0.1:'+r.port;
 const J=async(p,opts)=>{const res=await fetch(U+p,opts);let body=null;try{body=await res.json()}catch{}return{status:res.status,body}};
 const post=(p,obj,key)=>J(p,{method:'POST',headers:{'content-type':'application/json','x-gw-chat-key':key},body:JSON.stringify(obj)});

 // 1) chat auth: no key, wrong key -> 403; command token must NOT open chat routes
 assert((await J('/chat')).status===403,'chat: no key -> 403');
 assert((await J('/chat?key=nope')).status===403,'chat: wrong key -> 403');
 assert((await J('/chat?key='+TOKEN)).status===403,'chat: command token rejected on chat routes');
 assert(logs.some(l=>l.stage==='chat_auth_fail'),'chat auth failure audited');
 // command routes unchanged: chat token must NOT open them
 assert((await J('/health',{headers:{'X-GW-Key':CHAT}})).status===403,'cmd: chat token rejected on cmd routes');

 // 2) send (header key) + dedupe by id
 {const a=await post('/chat',{id:'m1',text:'שלום',at:1},CHAT);
  assert(a.status===200&&a.body.ok&&a.body.id==='m1','send ok: '+JSON.stringify(a.body));
  const b=await post('/chat',{id:'m1',text:'שלום',at:1},CHAT);
  assert(b.body.duplicate===true,'dedupe by id');}

 // 3) send via query key; empty text -> 400
 {const res=await fetch(U+'/chat?key='+CHAT,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:'m2',text:'שני'})});
  assert(res.status===200,'query key accepted');
  const e=await post('/chat',{id:'m3',text:'  '},CHAT);
  assert(e.status===400&&e.body.error==='text_too_short','empty text rejected');}

 // 4) history: after-cursor, order, shape the island parses
 {const h=await J('/chat?key='+CHAT+'&after=0');
  assert(h.status===200&&h.body.ok&&Array.isArray(h.body.messages)&&Array.isArray(h.body.cards),'history shape');
  assert(h.body.messages.length===2&&h.body.messages[0].id==='m1'&&h.body.messages[1].id==='m2','history order: '+JSON.stringify(h.body.messages));
  const m=h.body.messages[0];
  assert(typeof m.text==='string'&&typeof m.received_at==='number'&&typeof m.at==='number'&&typeof m.in_reply_to==='string','row fields');
  const c=await J('/chat?key='+CHAT+'&after='+h.body.messages[0].received_at);
  assert(c.body.messages.length===1&&c.body.messages[0].id==='m2','after-cursor filters');}

 // 5) agent-side reply (from=agent) appears in history
 {const a=await post('/chat',{id:'a1',text:'תשובה',from:'agent'},CHAT);
  assert(a.status===200,'agent send');
  const h=await J('/chat?key='+CHAT+'&after=0');
  assert(h.body.messages.some(m=>m.id==='a1'&&m.from==='agent'),'agent row present');}

 // 6) SSE: backlog + live row
 {const ctl=new AbortController();
  const res=await fetch(U+'/chat/stream?key='+CHAT+'&after=0',{signal:ctl.signal,headers:{accept:'text/event-stream'}});
  assert(res.status===200&&/text\/event-stream/.test(res.headers.get('content-type')||''),'stream opens');
  const reader=res.body.getReader();const dec=new TextDecoder();let buf='';
  const readUntil=async(mark,ms)=>{const t0=Date.now();while(Date.now()-t0<ms){const{done,value}=await reader.read();if(done)break;buf+=dec.decode(value,{stream:true});if(buf.includes(mark))return true}return false};
  assert(await readUntil('"m1"',3000),'stream replays backlog');
  await post('/chat',{id:'m9',text:'חי',at:2},CHAT);
  assert(await readUntil('"m9"',3000),'stream pushes live row');
  ctl.abort();}

 // 7) screenshot: stores bytes + adds a chat row with file ref
 {const png=Buffer.alloc(64,7).toString('base64');
  const s=await post('/chat/screenshot',{id:'s1',image:png,at:3},CHAT);
  assert(s.status===200&&s.body.ok,'shot accepted: '+JSON.stringify(s.body));
  assert(fs.existsSync(path.join(dir,'shots','s1.jpg')),'shot file written');
  const h=await J('/chat?key='+CHAT+'&after=0');
  const row=h.body.messages.find(m=>m.id==='s1');
  assert(row&&row.file&&row.file.size===64,'shot row with file ref');
  const big=await post('/chat/screenshot',{id:'s2',image:Buffer.alloc(4100000,1).toString('base64')},CHAT);
  assert(big.status===413,'oversize shot refused');}

 // 8) persistence: new chat instance over the same dir sees the rows
 {const chat2=createChat({dir,log:()=>{}});
  assert(chat2.count()===chat.count(),'rows survive reload ('+chat2.count()+')');
  assert(chat2.history(0,200).some(m=>m.id==='m1'),'m1 persisted');}

 // 9) one-time import of existing island history files
 {const dir2=fs.mkdtempSync(path.join(os.tmpdir(),'gwchat2-'));
  const roam=fs.mkdtempSync(path.join(os.tmpdir(),'gwroam-'));
  fs.writeFileSync(path.join(roam,'chat-x.json'),JSON.stringify({messages:[
   {id:'old1',dir:'out',text:'ישן',at:100,status:'sent'},
   {id:'old2',dir:'in',text:'תשובה ישנה',at:200,received_at:250},
   {id:'old3',dir:'out',text:'ממתין',at:300,status:'waiting'} // never sent - not imported
  ]}));
  const chat3=createChat({dir:dir2,log:()=>{}});
  const imp=chat3.importOnce([roam]);
  assert(imp.imported===2,'imported 2 (waiting skipped): '+imp.imported);
  const h=chat3.history(0,200);
  assert(h[0].id==='old1'&&h[0].from==='user'&&h[1].id==='old2'&&h[1].from==='agent','import mapping + order');
  const imp2=chat3.importOnce([roam]);
  assert(imp2.skipped===true&&imp2.imported===0,'import runs once');}

 await r.stop();
 console.log('server-chat-unit: all OK');
}
main().catch(e=>{console.error('FAIL:',e&&e.message);process.exit(1)});
