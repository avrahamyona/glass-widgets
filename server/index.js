// "החיים שלי השרתי" - the standalone own-server skeleton. Electron-free Node process.
// Eventually replaces the Cloudflare worker path: no quotas, no external dependency.
// Local build only - NOT deployed, NOT wired into any release.
//
// Trust model (same contract as the embedded leg): the baked token is PUBLIC and gates
// nothing private by itself. Commands arrive as Ed25519-signed envelopes {id,kind,ts,exp,
// sig,data[,device]} verified against the configured sender pubkey; reads are signed and
// device-bound; one transactional ledger gives at-most-once execution with durable evidence.
const fs=require('fs'),path=require('path'),crypto=require('crypto'),os=require('os');
const{startLocalServer}=require('../src/lib/localserver');
const{createLedger,RESULT_TTL_MS}=require('../src/lib/ledger');
const{OPS}=require('./lib/ops');
const{deriveCaps}=require('./lib/capabilities'); // A4: caps derive from the registry, never a hand-edited banner
const{fingerprint}=require('../src/lib/fingerprint'); // the PC-side fingerprint source the user compares against the approval request
const{RESERVED}=require('../src/lib/command-contract'); // shared reserved-field list

const CONFIG=process.env.GW_SERVER_CONFIG||path.join(process.env.GW_SERVER_DATA||path.join(os.homedir(),'.glasswidgets-server'),'config.json');
let cfg={}; // config.json is OPTIONAL: env-only provisioning must boot without any file
try{cfg=JSON.parse(fs.readFileSync(CONFIG,'utf8'))}catch(e){if(!e||e.code!=='ENOENT')throw e}
const dataDir=path.dirname(CONFIG);
// secrets: env wins, config.json is the LOCAL-DEV path only. Production provisioning is a
// vault/managed-secret handoff - the token and sender pubkey never sit in a repo or a backup.
cfg.token=process.env.GW_SERVER_TOKEN||cfg.token;
cfg.senderPub=process.env.GW_SENDER_PUB||cfg.senderPub;
if(!cfg.token||!cfg.senderPub)throw new Error('config requires token + senderPub (base64 SPKI)');
const roots=Array.isArray(cfg.roots)&&cfg.roots.length?cfg.roots:[path.join(os.homedir(),'Documents'),path.join(os.homedir(),'Desktop'),path.join(os.homedir(),'Downloads')].filter(p=>{try{return fs.statSync(p).isDirectory()}catch{return false}});

// device identity: generated ON this machine on first boot, private key never leaves
const devFile=path.join(dataDir,'device.json');
const{aclHarden,aclOwnerOnly}=require('../src/lib/acl-win'); // the SHARED reviewed harden+verify module (icacls + Get-Acl/evalAclDump verification), same code as the Electron agent
function hardenOrThrow(p,isDir){ // harden AND verify; explicit ACEs that /grant:r does not remove fail the verification -> we fail closed
 if(process.platform!=='win32')return;
 if(!aclHarden(p,isDir))throw new Error('ACL harden+verify failed on '+p);
}
function derivePub(privB64){
 const pub=crypto.createPublicKey(crypto.createPrivateKey({key:Buffer.from(privB64,'base64'),format:'der',type:'pkcs8'}));
 return pub.export({format:'der',type:'spki'}).toString('base64');
}
let device=null,devRaw=null,devExists=true;
try{fs.statSync(devFile)}catch(e){if(!e||e.code!=='ENOENT')throw e;devExists=false} // ONLY a missing file means first boot; stat failures fail CLOSED
if(devExists){
 // the agent's load order: dir AND file ACL verified BEFORE the private key is read or parsed -
 // write access to the DIR could replace the identity even when the file itself is owner-only
 if(process.platform==='win32'&&(!aclOwnerOnly(dataDir)||!aclOwnerOnly(devFile)))throw new Error('device identity ACL failed (dir or file not owner-only) - refusing to boot');
 devRaw=fs.readFileSync(devFile,'utf8');
 device=JSON.parse(devRaw); // a CORRUPT file throws here - boot fails loud, identity never silently renews
 if(!device||!device.priv||!device.pub||derivePub(device.priv)!==device.pub)throw new Error('device identity file failed the private/public pair check - refusing to boot over a corrupt identity');
 const want=crypto.createHash('sha256').update(device.pub).digest('hex').slice(0,16);
 if(device.id!==want)throw new Error('device id does not match its pubkey - refusing to boot over a corrupt identity');
}else{ // first boot ONLY: create the data dir private, harden+verify it, THEN mint (atomic unique-tmp + rename)
 fs.mkdirSync(dataDir,{recursive:true,mode:0o700}); // env-only provisioning: the dir may not exist yet
 hardenOrThrow(dataDir,true);
 const{publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
 device={pub:publicKey.export({format:'der',type:'spki'}).toString('base64'),priv:privateKey.export({format:'der',type:'pkcs8'}).toString('base64')};
 device.id=crypto.createHash('sha256').update(device.pub).digest('hex').slice(0,16);
 const tmp=path.join(dataDir,'.device-'+process.pid+'-'+Date.now()+'.tmp');
 try{
  fs.writeFileSync(tmp,JSON.stringify(device),{mode:0o600,flag:'wx'}); // exclusive create - a pre-planted tmp is never overwritten
  hardenOrThrow(tmp,false); // harden+verify BEFORE the rename
  fs.renameSync(tmp,devFile); // atomic same-dir rename
 }finally{try{fs.unlinkSync(tmp)}catch{}} // a failed mint never leaves a tmp behind
}
const privK=crypto.createPrivateKey({key:Buffer.from(device.priv,'base64'),format:'der',type:'pkcs8'});
const deviceSign=t=>crypto.sign(null,Buffer.from(t,'utf8'),privK).toString('hex');

const ledger=createLedger(path.join(dataDir,'ledger.json'));
const logFile=path.join(dataDir,'server-audit.log');
const log=(lvl,o)=>{try{fs.appendFileSync(logFile,JSON.stringify({at:new Date().toISOString(),lvl,...o})+'\n')}catch{}};

const{createVerifier}=require('./lib/verify');
const{verifyReadAuth,validEnvelope}=createVerifier({deviceId:device.id,senderPubB64:cfg.senderPub});
async function main(){
 const r=await startLocalServer({port:+(process.env.GW_SERVER_PORT||cfg.port||47700),host:process.env.GW_SERVER_HOST||cfg.host||'127.0.0.1',token:cfg.token,version:'server-0.1.0',caps:deriveCaps(OPS),
  getDevice:()=>({deviceId:device.id,deviceSign}),
  getTask:id=>ledger.get(id),tasksOk:()=>ledger.ok(),
  getInfo:()=>({envelopeVersions:['v1','v2'],deviceId:device.id,pubkey:device.pub,fingerprint:fingerprint(device.pub)}),
  verifyReadAuth,log,
  onCommand:(m)=>{
   if(!Object.prototype.hasOwnProperty.call(OPS,String(m.kind)))return {accepted:false,status:400,reason:'unknown_kind'};
   const data=(m.data&&typeof m.data==='object'&&!Array.isArray(m.data))?m.data:{};
   for(const k of RESERVED)if(k in data)return {accepted:false,status:400,reason:'reserved_field'};
   if(m.device!=null&&String(m.device)!==device.id){log('warn',{stage:'wrong_device',id:String(m.id||'').slice(0,40)});return {accepted:false,status:403,reason:'wrong_device'}}
   if(process.env.GW_SERVER_STRICT_ENVELOPES==='1'&&m.device==null)return {accepted:false,status:403,reason:'device_required'}; // opt-in strict: enrolled devices take v2 device-bound envelopes only (mirrors the agent's STRICT_ENVELOPES)
   if(!validEnvelope(m,JSON.stringify(data))){log('warn',{stage:'unsigned_cmd',id:String(m.id||'').slice(0,40)});return {accepted:false,status:403,reason:'unsigned'}}
   if(!ledger.ok())return {accepted:false,status:503,reason:'ledger'};
   if(ledger.has(m.id))return {accepted:false,status:409,reason:'duplicate'};
   const putR=ledger.put(m.id,{status:'accepted',exp:+m.exp});
   if(putR==='full')return {accepted:false,status:429,reason:'ledger_full'};
   if(putR!==true)return {accepted:false,status:503,reason:'ledger'};
   (async()=>{ // dispatch AFTER the durable commit; the running gate decides before any effect
    if(ledger.transition(m.id,'running')!==true){log('warn',{stage:'running_gate_fail',id:String(m.id).slice(0,40)});try{ledger.put(m.id,{status:'failed',note:'running gate failed'})}catch{}return}
    try{const out=await OPS[m.kind](data,{roots});
     const w=ledger.put(m.id,out.ok?{status:'done',note:m.kind+' ok',result:out.result}:{status:'failed',note:String(out.error||'failed')});
     if(w!==true)log('error',{stage:'terminal_put_failed',id:String(m.id).slice(0,40),reason:String(w)});
    }catch(e){let w2='thrown';try{w2=ledger.put(m.id,{status:'failed',note:'op error'})}catch{}if(w2!==true)log('error',{stage:'terminal_put_failed',id:String(m.id).slice(0,40),reason:String(w2)})}
   })();
   return {accepted:true};
  }});
 if(!r.started){console.error('not started:',r.reason);process.exit(1)}
 console.log('server up on 127.0.0.1:'+r.port,'device',device.id,'fingerprint',fingerprint(device.pub),'roots',roots.length); // the fingerprint is the LOCAL source of truth for pairing comparison
}
main().catch(e=>{console.error(e);process.exit(1)});
