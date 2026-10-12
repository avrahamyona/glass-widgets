// Agent lifecycle unit tests (Electron-free): stopped-during-park and stopped-during-approval/ACK.
// stop() must cancel every parked timer, drain every in-flight pairing op, and close the journal
// lease BEFORE a same-process restart re-acquires it - no stale timer, ack, or effect survives.
const assert=require('assert'),fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto'),http=require('http'),net=require('net');

// electron stub: agent.js imports {screen} at module top
const Module=require('module'),origLoad=Module._load;
Module._load=function(request){if(request==='electron')return {screen:{getPrimaryDisplay:()=>({size:{width:1920,height:1080}}),getAllDisplays:()=>[]}};return origLoad.apply(this,arguments)};

// durable-store gate (test 2): a receipt put can be held so stop() must prove it drains the op
const ds=require('../src/lib/durable-store.js');
const origCreate=ds.createFileOutbox;
let receiptGate=null;
ds.createFileOutbox=(dir,...rest)=>{const s=origCreate(dir,...rest);const op=s.put.bind(s);
 s.put=(id,rec)=>{if(receiptGate&&rec&&rec.receipt!=null)return receiptGate.then(()=>op(id,rec));return op(id,rec)};return s};

const KP=crypto.generateKeyPairSync('ed25519');
const PRIV=KP.privateKey,PUB_B64=KP.publicKey.export({format:'der',type:'spki'}).toString('base64');
const signEnv=(id,kind,ts,exp,payload)=>crypto.sign(null,Buffer.from([id,kind,String(ts),String(exp),payload].join('\n'),'utf8'),PRIV).toString('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const freePort=()=>new Promise(res=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>res(p))})});

const acks=[];
const startAckStub=async()=>{const srv=http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{try{acks.push(JSON.parse(b))}catch{};res.writeHead(200,{'content-type':'application/json'});res.end('{"updated":1}')})});await new Promise(r=>srv.listen(0,'127.0.0.1',r));return srv};

async function main(){
 const ackSrv=await startAckStub();const ackPort=ackSrv.address().port;
 process.env.GLASSWIDGETS_AGENT_CMD_KEY='lc-key';
 process.env.GLASSWIDGETS_AGENT_CMD_URL='http://127.0.0.1:1/no-sse'; // SSE intake refused fast; the test drives the local server leg
 process.env.GLASSWIDGETS_AGENT_ACK_URL='http://127.0.0.1:'+ackPort+'/ack';
 process.env.GLASSWIDGETS_AGENT_SIGN_PUB=PUB_B64;
 process.env.GLASSWIDGETS_TUNNEL_ENABLED='0';
 const AGENT=require('../src/lib/agent.js');
 const startOn=(profile)=>{const app={getPath:()=>profile,getVersion:()=>'lc-test'};
  const cards=[],settles=[];
  const h=AGENT({app,rd:()=>({}),wr:()=>{},chatKey:'',broadcastCard:c=>cards.push(c),broadcastSettle:(id,o)=>settles.push({id,o})});
  return {h,cards,settles}};
 const post=async(port,body)=>{const r=await fetch('http://127.0.0.1:'+port+'/cmd',{method:'POST',headers:{'X-GW-Key':'lc-key','content-type':'application/json'},body:JSON.stringify(body)});return {status:r.status,body:await r.json().catch(()=>null)}};
 const waitUp=async port=>{for(let i=0;i<60;i++){try{const r=await fetch('http://127.0.0.1:'+port+'/health',{headers:{'X-GW-Key':'lc-key'}});if(r.status===200)return}catch{}await sleep(100)}throw new Error('server did not start on '+port)};
 const enrollBody=id=>{const ts=Date.now(),exp=ts+120000,data={challenge:'lc-episode-01'};const payload=JSON.stringify(data);return{id,kind:'enroll_device',ts,exp,sig:signEnv(id,'enroll_device',ts,exp,payload),data}};
 const waitAck=async(id,pred,ms)=>{const t0=Date.now();while(Date.now()-t0<(ms||6000)){const a=acks.filter(a=>a.id===id&&(!pred||pred(a)));if(a.length)return a;await sleep(50)}return null};

 // ---------- 1) stopped-during-park ----------
 process.env.GLASSWIDGETS_APPROVAL_TTL_MS='1500';
 const prof1=fs.mkdtempSync(path.join(os.tmpdir(),'gw-life1-')),port1=await freePort();
 process.env.GLASSWIDGETS_LOCAL_SERVER_PORT=String(port1);
 process.env.GLASSWIDGETS_AGENT_FOLDERS=prof1;
 const A1=startOn(prof1);await waitUp(port1);
 const r1=await post(port1,enrollBody('lc-park-1'));
 assert(r1.status===202,'park enroll accepted: '+r1.status+' '+JSON.stringify(r1.body));
 assert(A1.cards.length===1&&String(A1.cards[0].id).startsWith('local-approve-'),'pairing card parked');
 const jf=path.join(prof1,'pairing-pending','lc-park-1.json');
 assert(fs.existsSync(jf),'journal record staged');
 assert(A1.h.__debug().timers===1,'one parked pairing timer tracked, got '+A1.h.__debug().timers);
 await A1.h.stop();
 const d1=A1.h.__debug();
 assert(d1.timers===0&&d1.ops===0&&d1.journalOpen===false,'A1 fully drained: '+JSON.stringify(d1));
 assert(fs.existsSync(jf),'parked record survives stop (no decision)');
 assert(!fs.existsSync(path.join(prof1,'device','device.json')),'no key persisted');
 const B1=startOn(prof1);await waitUp(port1); // same-process restart on the SAME profile
 const a1=await waitAck('lc-park-1',a=>a.status==='failed');
 assert(a1&&a1.length===1&&/cancelled/.test(a1[0].note),'recovery ack failed/cancelled exactly once: '+JSON.stringify(a1));
 assert(!fs.existsSync(jf),'journal record cleared after the verified terminal');
 assert(!fs.existsSync(path.join(prof1,'device','device.json')),'still no key');
 assert(B1.h.__debug().journalOpen===true,'B1 re-acquired the journal lease in the same process');
 await sleep(2200); // A1's pairing-expiry timer would have fired at ~1.5s if it had leaked
 const all1=acks.filter(a=>a.id==='lc-park-1');
 assert(all1.length===1&&!all1.some(a=>/expired/.test(a.note||'')),'no stale timer ack after stop+restart: '+JSON.stringify(all1));
 await B1.h.stop();
 console.log('LIFECYCLE stopped-during-park: PASS');

 // ---------- 2) stopped-during-approval/ACK (journal receipt write held) ----------
 process.env.GLASSWIDGETS_APPROVAL_TTL_MS='120000';
 const prof2=fs.mkdtempSync(path.join(os.tmpdir(),'gw-life2-')),port2=await freePort();
 process.env.GLASSWIDGETS_LOCAL_SERVER_PORT=String(port2);
 process.env.GLASSWIDGETS_AGENT_FOLDERS=prof2;
 const A2=startOn(prof2);await waitUp(port2);
 const r2=await post(port2,enrollBody('lc-appr-1'));
 assert(r2.status===202,'approve enroll accepted: '+r2.status+' '+JSON.stringify(r2.body));
 const cardId2=A2.cards[0].id;
 let releaseGate;receiptGate=new Promise(r=>releaseGate=r);
 const decision=AGENT.handleCardAction({card_id:cardId2,button_id:'approve'}); // tracked op, blocks on the gated journal receipt put
 await sleep(200);
 assert(A2.h.__debug().ops===1,'approval op in flight, got '+A2.h.__debug().ops);
 let stopped=false;const stopP=A2.h.stop().then(()=>{stopped=true});
 await sleep(200);
 assert(stopped===false,'stop() waits out the in-flight approval op (no journal close mid-write)');
 releaseGate();
 await stopP;assert(stopped===true,'stop resolved after the drain');
 await decision;
 const d2=A2.h.__debug();
 assert(d2.ops===0&&d2.journalOpen===false,'A2 drained: '+JSON.stringify(d2));
 // the FULL effect landed before the journal closed: key persisted, terminal committed+sent, record cleared
 const a2=await waitAck('lc-appr-1',a=>a.status==='done');
 assert(a2&&a2.length===1&&a2[0].result&&a2[0].result.deviceId,'exactly one done ack carrying the enrolled device: '+JSON.stringify(a2));
 assert(fs.existsSync(path.join(prof2,'device','device.json')),'key persisted');
 assert(!fs.existsSync(path.join(prof2,'pairing-pending','lc-appr-1.json')),'journal record cleared after the verified terminal');
 const B2=startOn(prof2);await waitUp(port2);
 await sleep(900);
 const all2=acks.filter(a=>a.id==='lc-appr-1');
 assert(all2.length===1,'no re-ack after restart: '+JSON.stringify(all2));
 assert(fs.readdirSync(path.join(prof2,'pairing-pending')).filter(f=>f.endsWith('.json')).length===0,'no leftover journal records');
 await B2.h.stop();
 console.log('LIFECYCLE stopped-during-approval/ACK: PASS');
 ackSrv.close();
 console.log('AGENT-LIFECYCLE-UNIT: PASS');
 process.exit(0);
}
main().catch(e=>{console.error('FAIL:',e&&e.message||e);process.exit(1)});
