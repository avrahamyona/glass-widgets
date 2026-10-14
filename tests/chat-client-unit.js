// chat-client: the responder side ("חיים") against a live local server - send/history/stream.
const{startLocalServer}=require('../src/lib/localserver');
const{createChat}=require('../server/lib/chat');
const cc=require('../server/lib/chat-client');
const fs=require('fs'),os=require('os'),path=require('path');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};

async function main(){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gwcc-'));
 const chat=createChat({dir,log:()=>{}});
 const r=await startLocalServer({port:0,token:'cmd-k',version:'t',caps:'chat',onCommand:()=>({accepted:true}),
  chat:{token:'chat-k',handle:(req,res,reply)=>chat.handle(req,res,reply)}});
 assert(r.started,'server up');
 const base='http://127.0.0.1:'+r.port+'/chat',TOK='chat-k';

 // user message arrives (simulated island), responder sees it, replies as agent
 await cc.send(base,TOK,'שאלה מהאי',{from:'user',id:'u1'});
 const h=await cc.history(base,TOK,0);
 assert(h.status===200&&h.body===undefined&&Array.isArray(h.messages),'history shape');
 assert(h.messages.length===1&&h.messages[0].id==='u1'&&h.messages[0].from==='user','user row');
 const rep=await cc.send(base,TOK,'תשובה מחיים',{from:'agent',inReplyTo:'u1',id:'r1'});
 assert(rep.status===200&&rep.ok&&rep.id==='r1','agent reply accepted: '+JSON.stringify(rep));
 const h2=await cc.history(base,TOK,h.messages[0].received_at);
 assert(h2.messages.length===1&&h2.messages[0].from==='agent'&&h2.messages[0].in_reply_to==='u1','reply row after cursor');

 // wrong token: nothing opens
 const bad=await cc.send(base,'nope','x',{});
 assert(bad.status===403,'wrong token refused');
 const badH=await cc.history(base,'nope',0);
 assert(badH.status===403,'wrong token refused on history');

 // stream: live row delivered
 const ctl=new AbortController();
 const got=[];
 const sp=cc.stream(base,TOK,0,{signal:ctl.signal,onRow:m=>got.push(m)});
 await new Promise(r2=>setTimeout(r2,300));
 await cc.send(base,TOK,'הודעה חיה',{from:'user',id:'u2'});
 const t0=Date.now();while(!got.some(m=>m.id==='u2')&&Date.now()-t0<4000)await new Promise(r2=>setTimeout(r2,100));
 assert(got.some(m=>m.id==='u2'),'stream delivered live row');
 assert(got.some(m=>m.id==='u1'),'stream replayed backlog');
 ctl.abort();await sp.catch(()=>{});
 await r.stop();
 console.log('chat-client-unit: all OK');
}
main().catch(e=>{console.error('FAIL:',e&&e.message);process.exit(1)});
