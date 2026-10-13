// Unit: worker/enroll-completion.js - the challenge-plan completion verifier. Real Ed25519
// episodes built through the PC-side modules (src/lib/enroll-challenge.js signChallenge,
// src/lib/fingerprint.js), then verified worker-side through the subtle port. FakeDB mirrors
// the D1 prepared-statement surface for BOTH tables.
const assert=require('assert'),crypto=require('crypto');
const{deviceIdFromPub}=require('../src/lib/enroll-challenge.js');
const{fingerprint:fpFn}=require('../src/lib/fingerprint.js');
const{verifyEnrollTerminal,recordPendingRegistration,confirmRegistration,APPROVAL_WINDOW_MS}=require('../worker/enroll-completion.js');
class FakeStmt{constructor(db,sql,args){this.db=db;this.sql=sql;this.args=args}
 async first(){const d=this.db,s=this.sql,a=this.args;
  if(s.startsWith('SELECT device_id,pubkey,challenge,approved_at,card_id FROM pending_registrations')){const r=d.pending.get(a[0]);return r?{device_id:r.device_id,pubkey:r.pubkey,challenge:r.challenge,approved_at:r.approved_at,card_id:r.card_id}:null}
  if(s.startsWith('SELECT device_id,pubkey,confirmed_at FROM pending_registrations')){const r=d.pending.get(a[0]);return r?{device_id:r.device_id,pubkey:r.pubkey,confirmed_at:r.confirmed_at}:null}
  if(s.startsWith('SELECT pubkey FROM devices')){const pk=d.devices.get(a[0]);return pk?{pubkey:pk.pubkey}:null}
  throw new Error('unexpected first: '+s)}
 async run(){const d=this.db,s=this.sql,a=this.args;
  if(s.startsWith('INSERT INTO pending_registrations')){
   if(d.pending.has(a[0]))throw new Error('PK');
   for(const r of d.pending.values())if(r.challenge===a[3])throw new Error('UNIQUE challenge');
   d.pending.set(a[0],{device_id:a[1],pubkey:a[2],challenge:a[3],approved_at:a[4],card_id:a[5],created_at:a[6],confirmed_at:null});return{meta:{changes:1}}}
  if(s.startsWith('INSERT INTO devices')){
   if(d.devices.has(a[0]))throw new Error('PK');
   if(d.devices.size>=a[3])return{meta:{changes:0}};
   d.devices.set(a[0],{pubkey:a[1],enrolled_at:a[2]});return{meta:{changes:1}}}
  if(s.startsWith('UPDATE pending_registrations SET confirmed_at')){const r=d.pending.get(a[1]);if(r)r.confirmed_at=a[0];return{meta:{changes:r?1:0}}}
  throw new Error('unexpected run: '+s)}}
class FakeDB{constructor(){this.pending=new Map();this.devices=new Map()}
 prepare(sql){const db=this;return{bind(...args){return new FakeStmt(db,sql,args)}}}}
function mintDevice(){const{publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
 const pubkey=publicKey.export({format:'der',type:'spki'}).toString('base64');
 const priv=privateKey.export({format:'der',type:'pkcs8'});
 return{pubkey,priv,deviceId:deviceIdFromPub(pubkey)}}
const cardId=cmdId=>'local-approve-'+crypto.createHash('sha256').update(String(cmdId),'utf8').digest('hex').slice(0,32);
function terminal(dev,cmdId,challenge,approvedAt,over={}){ // the PC terminal shape (agent.js execEnroll done)
 const sigHex=crypto.sign(null,Buffer.from([challenge,dev.pubkey,dev.deviceId].join('\n'),'utf8'),crypto.createPrivateKey({key:dev.priv,format:'der',type:'pkcs8'})).toString('hex');
 return{deviceId:dev.deviceId,pubkey:dev.pubkey,challengeSig:sigHex,
  pairing:{fingerprint:fpFn(dev.pubkey),approvedAt,cardId:cardId(cmdId)},...over}}
(async()=>{
 const now=Date.now();
 // 1. valid episode verifies, pends, confirms
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-1',ch='nonce-AAAA-1',ts=now-60000;
  const r=await verifyEnrollTerminal({cmdId:cmd,cmdTs:ts,challenge:ch,result:terminal(dev,cmd,ch,now-5000)});
  assert(r.ok===true&&r.device.deviceId===dev.deviceId&&r.device.pubkey===dev.pubkey,'valid terminal verifies');
  const p=await recordPendingRegistration(db,{cmdId:cmd,challenge:ch,device:r.device});
  assert(p.ok===true&&!p.already,'pending recorded');
  const p2=await recordPendingRegistration(db,{cmdId:cmd,challenge:ch,device:r.device});
  assert(p2.ok===true&&p2.already===true,'identical replay idempotent');
  const c=await confirmRegistration(db,cmd,2);
  assert(c.ok===true&&c.deviceId===dev.deviceId&&db.devices.get(dev.deviceId),'confirm registers');
  const c2=await confirmRegistration(db,cmd,2);
  assert(c2.ok===true&&c2.already===true,'re-confirm idempotent')}
 // 2. forged challenge proof refused
 {const dev=mintDevice();const t=terminal(dev,'cmd-2','nonce-BBBB-2',now-5000);
  t.challengeSig=crypto.sign(null,Buffer.from(['WRONG-CH',dev.pubkey,dev.deviceId].join('\n'),'utf8'),crypto.createPrivateKey({key:dev.priv,format:'der',type:'pkcs8'})).toString('hex');
  const r=await verifyEnrollTerminal({cmdId:'cmd-2',cmdTs:now-60000,challenge:'nonce-BBBB-2',result:t});
  assert(r.ok===false&&r.reason==='bad_challenge_sig','forged challenge sig refused')}
 // 3. self-declared deviceId refused
 {const dev=mintDevice();const t=terminal(dev,'cmd-3','nonce-CCCC-3',now-5000);
  t.deviceId='f'.repeat(16);
  const r=await verifyEnrollTerminal({cmdId:'cmd-3',cmdTs:now-60000,challenge:'nonce-CCCC-3',result:t});
  assert(r.ok===false&&(r.reason==='device_id_not_derived'||r.reason==='bad_challenge_sig'),'undeclared device id refused: '+r.reason)}
 // 4. tampered fingerprint refused
 {const dev=mintDevice();const t=terminal(dev,'cmd-4','nonce-DDDD-4',now-5000);
  t.pairing.fingerprint='0000-0000-0000-0000';
  const r=await verifyEnrollTerminal({cmdId:'cmd-4',cmdTs:now-60000,challenge:'nonce-DDDD-4',result:t});
  assert(r.ok===false&&r.reason==='fingerprint_mismatch','tampered fingerprint refused')}
 // 5. cardId of a DIFFERENT command refused
 {const dev=mintDevice();const t=terminal(dev,'cmd-5','nonce-EEEE-5',now-5000);
  t.pairing.cardId=cardId('cmd-OTHER');
  const r=await verifyEnrollTerminal({cmdId:'cmd-5',cmdTs:now-60000,challenge:'nonce-EEEE-5',result:t});
  assert(r.ok===false&&r.reason==='card_id_mismatch','foreign card id refused')}
 // 6. approvedAt window: before command / after window / future / non-integer
 {const dev=mintDevice();
  const before=await verifyEnrollTerminal({cmdId:'cmd-6a',cmdTs:now-60000,challenge:'nonce-FFFF-6',result:terminal(dev,'cmd-6a','nonce-FFFF-6',now-61000)});
  assert(before.ok===false&&before.reason==='approval_precedes_command','approval before command refused');
  const late=await verifyEnrollTerminal({cmdId:'cmd-6b',cmdTs:now-600000,challenge:'nonce-GGGG-6',result:terminal(dev,'cmd-6b','nonce-GGGG-6',now-1000)});
  assert(late.ok===false&&late.reason==='approval_window_exceeded','stale approval refused');
  const future=await verifyEnrollTerminal({cmdId:'cmd-6c',cmdTs:now-60000,challenge:'nonce-HHHH-6',result:terminal(dev,'cmd-6c','nonce-HHHH-6',now+120000)});
  assert(future.ok===false&&future.reason==='approval_in_future','future approval refused');
  const t=terminal(dev,'cmd-6d','nonce-IIII-6',now-5000);t.pairing.approvedAt=1.5;
  const frac=await verifyEnrollTerminal({cmdId:'cmd-6d',cmdTs:now-60000,challenge:'nonce-IIII-6',result:t});
  assert(frac.ok===false&&frac.reason==='bad_approved_at','non-integer approvedAt refused')}
 // 7. missing pairing evidence not registrable
 {const dev=mintDevice();const t=terminal(dev,'cmd-7','nonce-JJJJ-7',now-5000);delete t.pairing;
  const r=await verifyEnrollTerminal({cmdId:'cmd-7',cmdTs:now-60000,challenge:'nonce-JJJJ-7',result:t});
  assert(r.ok===false&&(r.reason==='missing_pairing_evidence'||r.reason==='result_shape'),'bare terminal refused: '+r.reason)}
 // 8. smuggled field in the terminal refused
 {const dev=mintDevice();const t=terminal(dev,'cmd-8','nonce-KKKK-8',now-5000);t.admin=true;
  const r=await verifyEnrollTerminal({cmdId:'cmd-8',cmdTs:now-60000,challenge:'nonce-KKKK-8',result:t});
  assert(r.ok===false&&r.reason==='result_shape','extra terminal field refused')}
 // 9. challenge replay: one-time nonce cannot back two registrations
 {const dev=mintDevice(),dev2=mintDevice(),db=new FakeDB();
  const r1=await verifyEnrollTerminal({cmdId:'cmd-9a',cmdTs:now-60000,challenge:'nonce-LLLL-9',result:terminal(dev,'cmd-9a','nonce-LLLL-9',now-5000)});
  assert((await recordPendingRegistration(db,{cmdId:'cmd-9a',challenge:'nonce-LLLL-9',device:r1.device})).ok);
  const r2=await verifyEnrollTerminal({cmdId:'cmd-9b',cmdTs:now-60000,challenge:'nonce-LLLL-9',result:terminal(dev2,'cmd-9b','nonce-LLLL-9',now-5000)});
  const p2=await recordPendingRegistration(db,{cmdId:'cmd-9b',challenge:'nonce-LLLL-9',device:r2.device});
  assert(p2.ok===false&&p2.reason==='episode_conflict','challenge replay refused');
  assert(db.pending.size===1,'only one pending record')}
 // 10. conflicting replay of the SAME cmd refused
 {const dev=mintDevice(),dev2=mintDevice(),db=new FakeDB();
  const r1=await verifyEnrollTerminal({cmdId:'cmd-10',cmdTs:now-60000,challenge:'nonce-MMMM-10',result:terminal(dev,'cmd-10','nonce-MMMM-10',now-5000)});
  assert((await recordPendingRegistration(db,{cmdId:'cmd-10',challenge:'nonce-MMMM-10',device:r1.device})).ok);
  const r2=await verifyEnrollTerminal({cmdId:'cmd-10',cmdTs:now-60000,challenge:'nonce-NNNN-10',result:terminal(dev2,'cmd-10','nonce-NNNN-10',now-5000)});
  const p2=await recordPendingRegistration(db,{cmdId:'cmd-10',challenge:'nonce-NNNN-10',device:r2.device});
  assert(p2.ok===false&&p2.reason==='episode_conflict','conflicting same-cmd replay refused')}
 // 11. device limit on confirm: pending survives
 {const dev=mintDevice(),db=new FakeDB();db.devices.set('a'.repeat(16),{pubkey:'x'});db.devices.set('b'.repeat(16),{pubkey:'y'});
  const r=await verifyEnrollTerminal({cmdId:'cmd-11',cmdTs:now-60000,challenge:'nonce-OOOO-11',result:terminal(dev,'cmd-11','nonce-OOOO-11',now-5000)});
  assert((await recordPendingRegistration(db,{cmdId:'cmd-11',challenge:'nonce-OOOO-11',device:r.device})).ok);
  const c=await confirmRegistration(db,'cmd-11',2);
  assert(c.ok===false&&c.reason==='device_limit','limit surfaces');
  assert(db.pending.has('cmd-11')&&db.pending.get('cmd-11').confirmed_at==null,'pending record survives the limit')}
 // 12. confirm without pending refused; already-registered same device idempotent via conflict path
 {const db=new FakeDB();
  const c=await confirmRegistration(db,'cmd-none',2);
  assert(c.ok===false&&c.reason==='no_pending','no pending refused')}
 console.log('WORKER-ENROLL-COMPLETION-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
