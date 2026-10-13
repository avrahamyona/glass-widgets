// Pointer-mailer unit tests: fake sockets, scripted replies. No network, no TLS, no real creds.
const{sendMail,buildMessage}=require('../server/lib/pointer-mailer');
const{EventEmitter}=require('events');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const USER='rehearsal.user@gmail.com',PASS='abcdefghijklmnop',FROM=USER,TO='me@gmail.com',SUBJ='GW-POINTER a1b2c3d4e5f60718';
const BODY='{"url":"https://a-b.trycloudflare.com","deviceId":"a1b2c3d4e5f60718","since":"2026-10-13T20:00:00.000Z","down":false}';

// Fake socket: scripted replies keyed by client WRITE ORDER (after banner). connect+banner via ticks.
function mkFake(script,{noBanner}={}){
 const s=new EventEmitter();s.connecting=true;s.writes=[];s.destroyed=false;
 s.write=d=>{s.writes.push(String(d));const r=script[s.writes.length-1];if(r!=null)setImmediate(()=>s.emit('data',Buffer.from(r+'\r\n')))};
 s.end=()=>{s.ended=true};s.destroy=()=>{s.destroyed=true};
 process.nextTick(()=>{s.connecting=false;s.emit('secureConnect');if(!noBanner)setImmediate(()=>s.emit('data',Buffer.from('220 smtp.example ESMTP\r\n')))});
 return s;
}
// replies are indexed by CLIENT WRITE ORDER: EHLO, AUTH, user, pass, MAIL, RCPT, DATA-start, message-end (QUIT needs none)
const FULL=['250 OK','334 VXNlcm5hbWU6','334 UGFzc3dvcmQ6','235 2.7.0 Accepted','250 2.1.0 OK','250 2.1.5 OK','354 End data with <CR><LF>.<CR><LF>','250 2.0.0 OK: queued'];
const watchdog=setTimeout(()=>{console.error('FAIL: global watchdog - a hung await would otherwise exit silently');process.exit(1)},8000);

async function main(){
 // 1) happy path: full submission, correct command sequence, credentials base64 on the wire
 {const sock=mkFake(FULL);
  const r=await sendMail({host:'smtp.example',port:465,user:USER,pass:PASS,from:FROM,to:TO,subject:SUBJ,text:BODY,socketImpl:sock,timeoutMs:2000});
  assert(r.ok===true,'submission accepted: '+JSON.stringify(r));
  const w=sock.writes;
  assert(w[0]==='EHLO glasswidgets-pc\r\n','EHLO first');
  assert(w[1]==='AUTH LOGIN\r\n','AUTH LOGIN second');
  assert(w[2]===Buffer.from(USER).toString('base64')+'\r\n','user base64');
  assert(w[3]===Buffer.from(PASS).toString('base64')+'\r\n','pass base64');
  assert(w[4]==='MAIL FROM:<'+FROM+'>\r\n'&&w[5]==='RCPT TO:<'+TO+'>\r\n'&&w[6]==='DATA\r\n','envelope commands');
  assert(w[7].includes('Subject: '+SUBJ)&&w[7].includes(BODY)&&w[7].endsWith('\r\n.\r\n'),'message ends with terminator');
  assert(w[8]==='QUIT\r\n','QUIT last')}

 // 2) auth reject (535) -> ok:false, stage auth_pass, reason NEVER carries the password
 {const sock=mkFake(FULL.slice(0,3).concat(['535 5.7.8 BadCredentials']));
  const r=await sendMail({host:'smtp.example',port:465,user:USER,pass:PASS,from:FROM,to:TO,subject:SUBJ,text:BODY,socketImpl:sock,timeoutMs:2000});
  assert(r.ok===false&&r.stage==='auth_pass','auth failure staged: '+JSON.stringify(r));
  assert(!JSON.stringify(r).includes(PASS)&&!JSON.stringify(r).includes(Buffer.from(PASS).toString('base64')),'password absent from failure')}

 // 3) rcpt reject -> staged failure
 {const sock=mkFake(FULL.slice(0,5).concat(['550 5.1.1 no such user']));
  const r=await sendMail({host:'smtp.example',port:465,user:USER,pass:PASS,from:FROM,to:TO,subject:SUBJ,text:BODY,socketImpl:sock,timeoutMs:2000});
  assert(r.ok===false&&r.stage==='rcpt_to','rcpt failure staged')}

 // 4) connect error -> ok:false, never throws
 {const sock=new EventEmitter();sock.connecting=true;sock.write=()=>{};sock.end=()=>{};sock.destroy=()=>{};
  process.nextTick(()=>sock.emit('error',new Error('ECONNREFUSED')));
  const r=await sendMail({host:'smtp.example',port:465,user:USER,pass:PASS,from:FROM,to:TO,subject:SUBJ,text:BODY,socketImpl:sock,timeoutMs:2000});
  assert(r.ok===false,'connect failure returned, not thrown: '+JSON.stringify(r))}

 // 5) silence timeout -> ok:false within ~timeoutMs, no hang
 {const sock=mkFake([],{noBanner:true});const t0=Date.now();
  const r=await sendMail({host:'smtp.example',port:465,user:USER,pass:PASS,from:FROM,to:TO,subject:SUBJ,text:BODY,socketImpl:sock,timeoutMs:200});
  assert(r.ok===false&&Date.now()-t0<1500,'timeout returns promptly: '+JSON.stringify(r))}

 // 6) multi-line reply handled (250-... then 250 ...)
 {const sock=mkFake(['250-smtp.example\r\n250-STARTTLS\r\n250 OK'].concat(FULL.slice(1))); // one WRITE, one multi-line reply
  const r=await sendMail({host:'smtp.example',port:465,user:USER,pass:PASS,from:FROM,to:TO,subject:SUBJ,text:BODY,socketImpl:sock,timeoutMs:2000});
  assert(r.ok===true,'multi-line EHLO reply consumed')}

 // 7) buildMessage: dot-stuffing, terminator, non-ASCII refusal
 {const m=buildMessage({from:FROM,to:TO,subject:SUBJ,text:'line1\r\n.line2\r\nline3'});
  assert(m.includes('\r\n..line2\r\n'),'leading dot stuffed');
  assert(m.endsWith('line3\r\n.\r\n'),'single-dot terminator');
  let t1=false;try{buildMessage({from:FROM,to:TO,subject:SUBJ,text:'עברית'})}catch(e){t1=e.message==='non_ascii_body'}
  assert(t1,'non-ASCII body refused before network');
  let t2=false;try{buildMessage({from:FROM,to:'x@y.z\nBCC: evil@x',subject:SUBJ,text:'a'})}catch(e){t2=true}
  assert(t2,'header injection refused')}

 clearTimeout(watchdog);
 console.log('POINTER-MAILER-UNIT: PASS');
}
main().catch(e=>{console.error('FAIL',e);process.exit(1)});
