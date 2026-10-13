// Unit: worker/enroll-completion.js v2 - the two-chain completion adapter. Chain A (issued
// episode + terminal possession proof) and chain B (independent owner approval binding) are
// exercised separately and joined. Includes ops's adversarial case: fabricated terminal
// pairing fields WITHOUT an owner approval record must never reach the registry.
const assert=require('assert'),crypto=require('crypto');
const{deviceIdFromPub}=require('../src/lib/enroll-challenge.js');
const{fingerprint:fpFn}=require('../src/lib/fingerprint.js');
const{verifyEnrollTerminal,verifyOwnerApproval,recordIssuedEpisode,recordApproval,confirmRegistration}=require('../worker/enroll-completion.js');
class FakeStmt{constructor(db,sql,args){this.db=db;this.sql=sql;this.args=args}
 async first(){const d=this.db,s=this.sql,a=this.args;const r=d.ep.get(a[0]);
  if(s.startsWith('SELECT challenge,issued_at,user_instruction_ref FROM enroll_episodes'))return r?{challenge:r.challenge,issued_at:r.issued_at,user_instruction_ref:r.uir}:null;
  if(s.startsWith('SELECT challenge,issued_at,status FROM enroll_episodes'))return r?{challenge:r.challenge,issued_at:r.issued_at,status:r.status}:null;
  if(s.startsWith('SELECT term_pubkey,approval_ref FROM enroll_episodes'))return r?{term_pubkey:r.term_pubkey,approval_ref:r.approval_ref}:null;
  if(s.startsWith('SELECT status,term_device_id,term_pubkey FROM enroll_episodes'))return r?{status:r.status,term_device_id:r.term_device_id,term_pubkey:r.term_pubkey}:null;
  if(s.startsWith('SELECT pubkey FROM devices')){const pk=d.devices.get(a[0]);return pk?{pubkey:pk.pubkey}:null}
  throw new Error('unexpected first: '+s)}
 async run(){const d=this.db,s=this.sql,a=this.args;
  if(s.startsWith('INSERT INTO enroll_episodes')){
   if(d.ep.has(a[0]))throw new Error('PK');
   for(const r of d.ep.values())if(r.challenge===a[1])throw new Error('UNIQUE challenge');
   d.ep.set(a[0],{challenge:a[1],issued_at:a[2],uir:a[3],status:'issued',term_device_id:null,term_pubkey:null,term_approved_at:null,approval_channel:null,approval_ref:null,approval_fingerprint:null,approved_at:null,confirmed_at:null});return{meta:{changes:1}}}
  if(s.startsWith("UPDATE enroll_episodes SET status='approved'")){
   const r=d.ep.get(a[7]);if(!r||r.status!=='issued')return{meta:{changes:0}};
   Object.assign(r,{status:'approved',term_device_id:a[0],term_pubkey:a[1],term_approved_at:a[2],approval_channel:a[3],approval_ref:a[4],approval_fingerprint:a[5],approved_at:a[6]});return{meta:{changes:1}}}
  if(s.startsWith("UPDATE enroll_episodes SET status='confirmed'")){
   const r=d.ep.get(a[1]);if(!r||r.status!=='approved')return{meta:{changes:0}};
   r.status='confirmed';r.confirmed_at=a[0];return{meta:{changes:1}}}
  if(s.startsWith('INSERT INTO devices')){
   if(d.devices.has(a[0]))throw new Error('PK');
   if(d.devices.size>=a[3])return{meta:{changes:0}};
   d.devices.set(a[0],{pubkey:a[1],enrolled_at:a[2]});return{meta:{changes:1}}}
  throw new Error('unexpected run: '+s)}}
class FakeDB{constructor(){this.ep=new Map();this.devices=new Map()}
 prepare(sql){const db=this;return{bind(...args){return new FakeStmt(db,sql,args)}}}}
function mintDevice(){const{publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
 const pubkey=publicKey.export({format:'der',type:'spki'}).toString('base64');
 return{pubkey,priv:privateKey.export({format:'der',type:'pkcs8'}),deviceId:deviceIdFromPub(pubkey)}}
const cardId=cmdId=>'local-approve-'+crypto.createHash('sha256').update(String(cmdId),'utf8').digest('hex').slice(0,32);
const sign=(priv,t)=>crypto.sign(null,Buffer.from(String(t),'utf8'),crypto.createPrivateKey({key:priv,format:'der',type:'pkcs8'})).toString('hex');
function terminal(dev,cmdId,challenge,approvedAt,over={}){ // the PC done-terminal shape; over() tampers
 const t={deviceId:dev.deviceId,pubkey:dev.pubkey,challengeSig:sign(dev.priv,[challenge,dev.pubkey,dev.deviceId].join('\n')),
  pairing:{fingerprint:fpFn(dev.pubkey),approvedAt,cardId:cardId(cmdId)}};
 return{...t,...over}}
const approval=(cmdId,fp,over={})=>({channel:'whatsapp',ref:'wamid.HBgMOTcyNTQ5OTE3MzcyFQIAEhgUM0FF',cmdId,fingerprint:fp,approvedAt:Date.now(),...over});
(async()=>{
 const now=Date.now();
 // 1. full two-chain path
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-1',ch='nonce-AAAA-1',ts=now-60000;
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:ts,userInstructionRef:'wa-msg-user-asked-enroll'})).ok,'episode issued');
  const term=terminal(dev,cmd,ch,now-5000);
  const ap=approval(cmd,fpFn(dev.pubkey),{approvedAt:now-4000});
  const r=await recordApproval(db,cmd,term,ap);
  assert(r.ok===true&&r.device.deviceId===dev.deviceId,'both chains join');
  const c=await confirmRegistration(db,cmd,2);
  assert(c.ok===true&&db.devices.get(dev.deviceId).pubkey===dev.pubkey,'registered');
  assert((await confirmRegistration(db,cmd,2)).already===true,'re-confirm idempotent');
  const r2=await recordApproval(db,cmd,term,ap);
  assert(r2.ok===true&&r2.already===true,'same-evidence replay idempotent')}
 // 2. OPS ADVERSARIAL: fabricated pairing fields, correct sig, NO owner approval -> nothing
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-2',ch='nonce-BBBB-2',ts=now-60000;
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:ts,userInstructionRef:'r'})).ok);
  const forged=terminal(dev,cmd,ch,now-5000); // self-minted key + fabricated cardId/fingerprint/approvedAt
  const v=await verifyEnrollTerminal({cmdId:cmd,cmdTs:ts,challenge:ch,result:forged,now});
  assert(v.ok===true,'pure verifier still passes possession (preparation only, NOT authority)');
  const r=await recordApproval(db,cmd,forged,null);
  assert(r.ok===false&&r.reason==='owner_missing_owner_approval','no approval record: no transition');
  const c=await confirmRegistration(db,cmd,2);
  assert(c.ok===false&&c.reason==='owner_approval_required','no approval: no INSERT');
  assert(db.devices.size===0&&db.ep.get(cmd).status==='issued','registry untouched, episode still issued')}
 // 3. approval bound to a DIFFERENT fingerprint refused
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-3',ch='nonce-CCCC-3';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const r=await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval(cmd,'0000-0000-0000-0000'));
  assert(r.ok===false&&r.reason==='owner_approval_fingerprint_mismatch','wrong fingerprint refused')}
 // 4. approval naming a DIFFERENT cmd refused
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-4',ch='nonce-DDDD-4';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const r=await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval('cmd-OTHER',fpFn(dev.pubkey)));
  assert(r.ok===false&&r.reason==='owner_approval_cmd_mismatch','foreign cmd approval refused')}
 // 5. non-allowlisted channel refused
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-5',ch='nonce-EEEE-5';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const r=await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval(cmd,fpFn(dev.pubkey),{channel:'email'}));
  assert(r.ok===false&&r.reason==='owner_approval_channel_not_allowed','email channel refused')}
 // 6. STRICT types: string approvedAt refused in BOTH chains
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-6',ch='nonce-FFFF-6';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const t=terminal(dev,cmd,ch,now-5000);t.pairing.approvedAt=String(now-5000);
  const v=await verifyEnrollTerminal({cmdId:cmd,cmdTs:now-60000,challenge:ch,result:t,now});
  assert(v.ok===false&&v.reason==='bad_approved_at','string terminal approvedAt refused');
  const r=await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval(cmd,fpFn(dev.pubkey),{approvedAt:String(now-4000)}));
  assert(r.ok===false&&r.reason==='owner_bad_approval_time','string approval approvedAt refused')}
 // 7. terminal against an UNISSUED episode refused
 {const dev=mintDevice(),db=new FakeDB();
  const r=await recordApproval(db,'cmd-never',terminal(dev,'cmd-never','nonce-GGGG-7',now-5000),approval('cmd-never',fpFn(dev.pubkey)));
  assert(r.ok===false&&r.reason==='no_issued_episode','unissued episode refused')}
 // 8. confirm BEFORE approval refused; approval with smuggled field refused
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-8',ch='nonce-HHHH-8';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const c=await confirmRegistration(db,cmd,2);
  assert(c.ok===false&&c.reason==='owner_approval_required','confirm before approval refused');
  const r=await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),{...approval(cmd,fpFn(dev.pubkey)),note:'x'});
  assert(r.ok===false&&r.reason==='owner_approval_shape','smuggled approval field refused')}
 // 9. one-time challenge at ISSUANCE: same challenge twice refused
 {const db=new FakeDB();
  assert((await recordIssuedEpisode(db,{cmdId:'cmd-9a',challenge:'nonce-IIII-9',issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const p=await recordIssuedEpisode(db,{cmdId:'cmd-9b',challenge:'nonce-IIII-9',issuedAt:now-60000,userInstructionRef:'r'});
  assert(p.ok===false&&p.reason==='episode_conflict','challenge replay at issuance refused');
  assert((await recordIssuedEpisode(db,{cmdId:'cmd-9a',challenge:'nonce-IIII-9',issuedAt:now-60000,userInstructionRef:'r'})).already===true,'identical issuance replay idempotent')}
 // 10. device limit: approved row survives
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-10',ch='nonce-JJJJ-10';
  db.devices.set('a'.repeat(16),{pubkey:'x'});db.devices.set('b'.repeat(16),{pubkey:'y'});
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  assert((await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval(cmd,fpFn(dev.pubkey)))).ok);
  const c=await confirmRegistration(db,cmd,2);
  assert(c.ok===false&&c.reason==='device_limit','limit surfaces');
  assert(db.ep.get(cmd).status==='approved','approved episode survives the limit')}
 // 11. re-approval with DIFFERENT evidence refused (replay safety after transition)
 {const dev=mintDevice(),dev2=mintDevice(),db=new FakeDB(),cmd='cmd-11',ch='nonce-KKKK-11';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  assert((await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval(cmd,fpFn(dev.pubkey)))).ok);
  const r=await recordApproval(db,cmd,terminal(dev2,cmd,ch,now-5000),approval(cmd,fpFn(dev2.pubkey)));
  assert(r.ok===false&&r.reason==='episode_not_issued','different evidence after approval refused');
  assert(db.ep.get(cmd).term_pubkey===dev.pubkey,'original evidence intact')}
 // 12. approval ref shape: spaces refused, wamid accepted (used throughout)
 {const dev=mintDevice(),db=new FakeDB(),cmd='cmd-12',ch='nonce-LLLL-12';
  assert((await recordIssuedEpisode(db,{cmdId:cmd,challenge:ch,issuedAt:now-60000,userInstructionRef:'r'})).ok);
  const r=await recordApproval(db,cmd,terminal(dev,cmd,ch,now-5000),approval(cmd,fpFn(dev.pubkey),{ref:'not a ref'}));
  assert(r.ok===false&&r.reason==='owner_bad_approval_ref','spacey ref refused')}
 console.log('WORKER-ENROLL-COMPLETION-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
