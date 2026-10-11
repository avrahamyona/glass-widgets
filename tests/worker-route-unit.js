// Unit tests for worker/tunnel-route.js with an in-memory fake D1 implementing exactly the
// statements the route uses. Covers: tombstone clear (publish100->clear200->replay100 rejected),
// monotonic ordering, device limit on enrollment, SPKI validation, header auth, body cap.
const assert=require('assert'),crypto=require('crypto');
const {handleTunnel,signEnrollCommand}=require('../worker/tunnel-route.js');

class FakeStmt{constructor(db,sql,args){this.db=db;this.sql=sql;this.args=args}
 async first(){const d=this.db,s=this.sql,a=this.args;
  if(s.includes('SELECT pubkey FROM devices')){const pk=d.devices.get(a[0]);return pk?{pubkey:pk.pubkey}:null}
  if(s.includes('COUNT(*)'))return{n:d.devices.size};
  if(s.includes('FROM tunnel_pointer p JOIN devices')){const p=d.ptr.get(a[0]);const dev=d.devices.get(a[0]);return p&&dev?{url:p.url,v:p.v,ts:p.ts,at:p.at,pubkey:dev.pubkey}:null}
  throw new Error('unexpected first: '+s)}
 async run(){const d=this.db,s=this.sql,a=this.args;
  if(s.startsWith('INSERT INTO devices')&&s.includes('WHERE (SELECT COUNT(*)')){ // atomic conditional insert
   if(d.devices.size>=a[3])return{meta:{changes:0}};
   d.devices.set(a[0],{pubkey:a[1],enrolled_at:a[2]});return{meta:{changes:1}}}
  if(s.startsWith('INSERT INTO devices')){d.devices.set(a[0],{pubkey:a[1],enrolled_at:a[2]});return{meta:{changes:1}}}
  if(s.startsWith('INSERT INTO tunnel_pointer')){
   const[id,url,v,ts,at]=a;const cur=d.ptr.get(id);
   if(cur&&!(ts>cur.ts))return{meta:{changes:0}}; // WHERE excluded.ts>tunnel_pointer.ts
   d.ptr.set(id,{url,v,ts,at});return{meta:{changes:1}}}
  throw new Error('unexpected run: '+s)}}
class FakeDB{constructor(){this.devices=new Map();this.ptr=new Map()}
 prepare(sql){const db=this;const bare=new FakeStmt(db,sql,[]);return{bind(...args){return new FakeStmt(db,sql,args)},first:()=>bare.first(),run:()=>bare.run()}}}

const{publicKey:PUB,privateKey:PRIV}=crypto.generateKeyPairSync('ed25519');
const PUB_B64=PUB.export({format:'der',type:'spki'}).toString('base64');
const devSign=(id,u,ts)=>crypto.sign(null,Buffer.from(id+'\n'+u+'\n'+ts,'utf8'),PRIV).toString('hex');
const DEVID=crypto.createHash('sha256').update(PUB_B64).digest('hex').slice(0,16);
const U='https://abc-123.trycloudflare.com';
const req=(method,path,{key='k',body,headers={}}={})=>new Request('http://w'+path,{method,headers:{'X-GW-Reply-Key':key,'content-type':'application/json',...headers},body:body?JSON.stringify(body):undefined});
const post=(env,path,body,opts)=>handleTunnel(req('POST',path,{...opts,body}),env,new URL('http://w'+path));
const get=(env,path,opts)=>handleTunnel(req('GET',path,opts),env,new URL('http://w'+path));

(async()=>{
 // missing env -> fail closed
 let r=await handleTunnel(req('GET','/glasswidgets/agent/tunnel?device='+DEVID),{},new URL('http://w/glasswidgets/agent/tunnel?device='+DEVID));
 assert(r.status===503,'missing env -> 503');
 const env={AVI_ACCOUNT_DB:new FakeDB(),GW_REPLY_KEY:'k'};
 // auth: wrong/missing sender key
 r=await get(env,'/glasswidgets/agent/tunnel?device='+DEVID,{key:'wrong'});
 assert(r.status===403,'wrong sender key -> 403');
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:DEVID,pubkey:PUB_B64},{key:'wrong'});
 assert(r.status===403,'enroll without sender key -> 403');
 // enroll: bad id / bad pubkey / id-pubkey binding / ok / atomic limit / idempotent re-enroll
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:'xyz',pubkey:PUB_B64});
 assert(r.status===400,'bad device id -> 400');
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:DEVID,pubkey:Buffer.from('not a key').toString('base64')});
 assert(r.status===400,'non-SPKI pubkey -> 400 bad_pubkey');
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:'aaaa0000bbbb1111',pubkey:PUB_B64});
 assert(r.status===400,'device_id NOT derived from the pubkey -> 400 bad_id');
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:DEVID,pubkey:PUB_B64});
 assert(r.status===200,'enroll ok');
 const k2=crypto.generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).toString('base64');
 const id2=crypto.createHash('sha256').update(k2).digest('hex').slice(0,16);
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:id2,pubkey:k2});
 assert(r.status===200,'second device ok (default limit 2)');
 const k3=crypto.generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).toString('base64');
 const id3=crypto.createHash('sha256').update(k3).digest('hex').slice(0,16);
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:id3,pubkey:k3});
 assert(r.status===409,'third device -> 409 device_limit (enforced INSIDE the insert)');
 r=await post(env,'/glasswidgets/agent/enroll',{device_id:DEVID,pubkey:PUB_B64});
 assert(r.status===200,'re-enroll same id+pubkey idempotent (no slot consumed)');
 // publish / ordering / TOMBSTONE
 const t0=Date.now()-5000;
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:U,v:'0.4.62',ts:t0,sig:devSign(DEVID,U,t0)});
 assert(r.status===200,'publish t0 ok');
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:U,v:'0.4.62',ts:t0-1000,sig:devSign(DEVID,U,t0-1000)});
 assert(r.status===409,'older publish -> 409 stale_publish (out-of-order never overwrites)');
 // THE tombstone case ops reproduced: publish(t0) -> clear(t0+2000) -> replay(t0) must be 409
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:'',ts:t0+2000,sig:devSign(DEVID,'',t0+2000)});
 assert(r.status===200,'clear with newer ts ok (tombstone)');
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:U,v:'0.4.62',ts:t0,sig:devSign(DEVID,U,t0)});
 assert(r.status===409,'TOMBSTONE: replayed old publish after clear -> 409, pointer stays dead');
 r=await get(env,'/glasswidgets/agent/tunnel?device='+DEVID);
 let j=await r.json();
 assert(j.down===true&&j.url===''&&j.stale===true&&j.pubkey===PUB_B64,'GET on a tombstone -> down:true, no url, pubkey present');
 // a newer publish revives
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:U,v:'0.4.62',ts:t0+3000,sig:devSign(DEVID,U,t0+3000)});
 assert(r.status===200,'newer publish after tombstone ok');
 r=await get(env,'/glasswidgets/agent/tunnel?device='+DEVID);
 j=await r.json();
 assert(j.url===U&&j.down===undefined&&j.stale===false,'revived pointer fresh');
 // bad sig / unenrolled / bad url / freshness
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:U,ts:t0+4000,sig:'ab'.repeat(64)});
 assert(r.status===403,'bad sig -> 403');
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:'aaaa0000bbbb1111',url:U,ts:t0+4000,sig:devSign('aaaa0000bbbb1111',U,t0+4000)});
 assert(r.status===403,'sig mismatch against enrolled pubkey -> 403');
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:'https://evil.example',ts:t0+4000,sig:devSign(DEVID,'https://evil.example',t0+4000)});
 assert(r.status===400,'non-trycloudflare url -> 400');
 r=await post(env,'/glasswidgets/agent/tunnel',{deviceId:DEVID,url:U,ts:Date.now()-600000,sig:devSign(DEVID,U,Date.now()-600000)});
 assert(r.status===400,'stale signed ts -> 400');
 // body cap: fast-path content-length AND streaming bytes (lying/absent length cannot bypass)
 const big='x'.repeat(5000);
 r=await handleTunnel(new Request('http://w/glasswidgets/agent/tunnel',{method:'POST',headers:{'X-GW-Reply-Key':'k','content-type':'application/json','content-length':'5000'},body:big}),env,new URL('http://w/glasswidgets/agent/tunnel'));
 assert(r.status===400,'over-cap body (declared) -> 400');
 r=await handleTunnel(new Request('http://w/glasswidgets/agent/tunnel',{method:'POST',headers:{'X-GW-Reply-Key':'k','content-type':'application/json'},body:big}),env,new URL('http://w/glasswidgets/agent/tunnel'));
 assert(r.status===400,'over-cap body (streamed, no declared length) -> 400 (byte-bounded read)');
 const okBody=JSON.stringify({deviceId:DEVID,url:U,v:'0.4.62',ts:0,sig:'ab'.repeat(64)});
 r=await handleTunnel(new Request('http://w/glasswidgets/agent/tunnel',{method:'POST',headers:{'X-GW-Reply-Key':'k','content-type':'application/json'},body:okBody}),env,new URL('http://w/glasswidgets/agent/tunnel'));
 assert(r.status===400,'within-cap streamed body reaches validation (stale ts -> 400), not rejected by the cap');
 // signEnrollCommand: live binding GW_SIGN_PRIVATE, payload EXACTLY '' (the PC contract) -
 // verified against the test pubkey with the PC-side validPreapproval shape
 const wenv={GW_SIGN_PRIVATE:PRIV.export({format:'der',type:'pkcs8'}).toString('base64')};
 const cmd=await signEnrollCommand(wenv,'enroll-1');
 assert(cmd.kind==='enroll_device'&&cmd.ts>0&&cmd.exp===cmd.ts+300000&&!('data' in cmd),'enroll envelope shape (no fields in stage 1)');
 const ok=crypto.verify(null,Buffer.from(['enroll-1','enroll_device',String(cmd.ts),String(cmd.exp),''].join('\n'),'utf8'),PUB,Buffer.from(cmd.sig,'hex'));
 assert(ok,'signEnrollCommand signs over the EMPTY payload - exactly what the PC verifies');
 let threw=false;try{await signEnrollCommand({},'x')}catch(e){threw=true}
 assert(threw,'missing GW_SIGN_PRIVATE throws (never signs with the wrong binding)');
 console.log('WORKER-ROUTE-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
