// Production sender outbox: durable, atomic, fail-closed. One JSON file per command id under a
// private dir. Contract:
//  DURABILITY: tmp(exclusive wx, mode 600) -> full-buffer writeSync LOOP -> fsync(file) ->
//  atomic same-dir rename -> fsync(DIRECTORY). A failed write/file-fsync/rename returns false and
//  removes the tmp: the PREVIOUS final record stays intact. A failed DIRECTORY fsync lands in the
//  committed-but-unverified state: the record exists on disk (get returns it), put returns false,
//  and an idempotent re-put re-runs the directory fsync before confirming - unverified durability
//  is never promoted to success without a fresh sync. (On win32, where libuv cannot open/fsync a
//  directory handle, the dir-fsync step is recorded once in outbox.notes as unsupported and the
//  rename relies on the NTFS journal; every other platform fails closed.)
//  FAIL-CLOSED READS: missing = null; CORRUPT / non-object / symlink / non-regular THROWS; on
//  POSIX a record whose owner uid or mode (must be 600) is wrong THROWS; on win32 a record that
//  is not SID-exact owner-only (shared acl-win verify) THROWS.
//  CONCURRENCY: a single-writer lease (.outbox.lock, wx-create, pid+host, full-write loop) is held
//  for the instance's lifetime. A live same-host holder blocks any second opener. A dead-pid lock
//  is reclaimed under a MUTUAL-EXCLUSION GUARD (.outbox.reclaim, atomic mkdir; stale guards are
//  cleared by unlink + atomic rmdir - exactly one racer wins): the guard holder re-reads the main
//  lock FRESH and unlinks it only if it is STILL dead, so a fresh opener's lock is never removed.
//  The tmp sweep runs ONLY after the lease is held and only over our tmp shape. put is an
//  immutable-envelope CAS: the serialized envelope under an id can never change (conflict throws),
//  receipt may only advance null->set, an identical re-put is idempotent (with re-sync, above).
//  close() releases the lease; get/put after close throw.
//  PRIVACY: the dir must not be a symlink. POSIX: enforced to mode 700 + owner uid verified.
//  win32: the dir must live under the user profile AND pass the shared SID-exact owner-only ACL
//  verify - existing dirs/records that fail it are hardened via the shared acl-win helper and
//  re-verified, else the store refuses to open (notes carry no security claim; the verify is the
//  gate). Record files are written 600 and hardened before rename.
const fs=require('fs'),path=require('path'),os=require('os');
const{strictId}=require('./command-contract'); // the ledger's id shape - also the filename boundary (no traversal)
const{aclOwnerOnly,aclHarden}=require('./acl-win'); // shared SID-exact harden+verify; no-ops true off-win32
// win32 dir-fsync limitation policy: libuv cannot open/fsync a directory handle there. The
// exact code varies by Node version. NARROWED (ops review): the codes are NOT interchangeable.
//   EINVAL/EBADF/ENOTSUP  - older fsync-on-directory limitation (either stage): note path.
//   EPERM/EACCES          - ONLY when raised at the OPEN stage (newer Node maps the directory
//                           open's ERROR_ACCESS_DENIED to EPERM) AND corroborated: the same
//                           directory is demonstrably listable right now (readdir probe) - i.e.
//                           it is the known handle-open limitation, not a real permission loss.
//                           The same code at the FSYNC stage, or with a failed probe, fails closed.
//   anything else (EIO, ...) and every code off-win32: fail closed.
// DURABILITY BOUNDARY (documented, not hidden): on the note path the rename's durability relies
// on the NTFS journal; the directory entry is NOT fsynced by us. The record body itself IS
// fsynced before rename. Exported (underscore) for unit tests only.
const dirFsyncUnsupportedOnWin=(isWin,e,stage,probeOk)=>{
 if(!isWin||!e)return false;
 if(e.code==='EINVAL'||e.code==='EBADF'||e.code==='ENOTSUP')return true;
 if(e.code==='EPERM'||e.code==='EACCES')return stage==='open'&&probeOk===true;
 return false};
function createFileOutbox(dir,opts){
 opts=opts||{};
 if(!dir)throw new Error('outbox needs a dir');
 const isWin=process.platform==='win32';
 const notes=[];
 // --- privacy boundary: no symlink dir, enforced mode/owner on POSIX, profile-rooted + ACL-verified on win32 ---
 const lst=fs.lstatSync(dir,{throwIfNoEntry:false});
 if(lst&&lst.isSymbolicLink())throw new Error('outbox dir is a symlink');
 if(!lst)fs.mkdirSync(dir,{recursive:true,mode:0o700});
 const st=fs.lstatSync(dir);
 if(st.isSymbolicLink())throw new Error('outbox dir is a symlink');
 if(!st.isDirectory())throw new Error('outbox dir is not a directory');
 if(isWin){
  const home=path.resolve(os.homedir()),real=path.resolve(dir);
  if(real!==home&&!real.startsWith(home+path.sep))throw new Error('outbox dir must live under the user profile on Windows');
  if(lst){if(!aclOwnerOnly(dir)&&!aclHarden(dir,true))throw new Error('outbox dir ACL is not owner-only and could not be hardened')} // an existing dir must PROVE SID-exact owner-only
  else if(!aclHarden(dir,true))throw new Error('outbox dir ACL hardening failed');
 }else{
  if(typeof st.uid==='number'&&st.uid!==process.getuid())throw new Error('outbox dir owned by another uid');
  if((st.mode&0o777)!==0o700){fs.chmodSync(dir,0o700);const st2=fs.lstatSync(dir);if((st2.mode&0o777)!==0o700)throw new Error('outbox dir mode not 700 after chmod');}
 }
 const writeFull=(fd,buf)=>{let off=0;while(off<buf.length){const n=fs.writeSync(fd,buf,off,buf.length-off);if(!(n>0))throw new Error('short write');off+=n}};
 // --- single-writer lease with guarded dead-pid reclaim ---
 const lockPath=path.join(dir,'.outbox.lock');
 const guardDir=path.join(dir,'.outbox.reclaim');
 const guardPidFile=path.join(guardDir,'pid');
 const holder=()=>{try{return JSON.parse(fs.readFileSync(lockPath,'utf8'))}catch{return null}};
 const alive=h=>{try{process.kill(h.pid,0);return true}catch(e){return e&&e.code==='EPERM'}};
 const deadHere=h=>!!(h&&h.host===os.hostname()&&typeof h.pid==='number'&&!alive(h));
 const heldErr=h=>new Error('outbox lease held by '+(h?('pid '+h.pid+' on '+h.host):'an unreadable lock'));
 const acquireGuard=()=>{ // mutual exclusion for reclaim: atomic mkdir; a stale guard is cleared by unlink+atomic rmdir (exactly one racer wins)
  try{fs.mkdirSync(guardDir)}catch(e){
   if(!(e&&e.code==='EEXIST'))throw e;
   const g=(()=>{try{return JSON.parse(fs.readFileSync(guardPidFile,'utf8'))}catch{return null}})();
   if(g&&!deadHere(g))throw new Error('outbox lease reclaim in progress (pid '+g.pid+')'); // live reclaimer (or unverifiable foreign host): refuse
   if(!g){ // publish gap or crash residue: a LIVE reclaimer exposes its pid within ms, so a fresh pidless guard is LIVE - refuse; only an old one is residue
    let age=Infinity;try{age=Date.now()-fs.statSync(guardDir).mtimeMs}catch{}
    if(age<60000)throw new Error('outbox lease reclaim in progress (unpublished guard)');
   }
   try{fs.unlinkSync(guardPidFile)}catch{}
   try{fs.rmdirSync(guardDir)}catch{throw new Error('outbox lease reclaim in progress')} // lost the rmdir race
   fs.mkdirSync(guardDir); // EEXIST here = lost to a fresher reclaimer
  }
  const fd=fs.openSync(guardPidFile,'wx',0o600);
  writeFull(fd,Buffer.from(JSON.stringify({pid:process.pid,host:os.hostname()}),'utf8'));
  fs.closeSync(fd);
 };
 const releaseGuard=()=>{try{fs.unlinkSync(guardPidFile)}catch{};try{fs.rmdirSync(guardDir)}catch{}};
 const acquire=()=>{
  try{
   const fd=fs.openSync(lockPath,'wx',0o600);
   writeFull(fd,Buffer.from(JSON.stringify({pid:process.pid,host:os.hostname(),at:Date.now()}),'utf8'));
   fs.closeSync(fd);
  }catch(e){
   if(!(e&&e.code==='EEXIST'))throw e;
   if(!deadHere(holder()))throw heldErr(holder());
   acquireGuard(); // exactly one concurrent reclaimer proceeds past this line
   try{
    const h2=holder(); // FRESH read under the guard: a fresh opener may have won the lock since our first read
    if(!deadHere(h2))throw heldErr(h2);
    fs.unlinkSync(lockPath);
   }finally{releaseGuard()}
   acquire(); // retry the exclusive create; a fresh opener in between wins and we refuse normally
  }
 };
 acquire();
 let closed=false;
 const release=()=>{if(closed)return;closed=true;process.removeListener('exit',release);try{fs.unlinkSync(lockPath)}catch{}};
 process.once('exit',release); // best-effort on crash-adjacent exits; a hard kill leaves a dead-pid lock that the next opener reclaims
 // --- stale tmp sweep: only now, only under the lease, only our tmp shape ---
 try{for(const f of fs.readdirSync(dir))if(/^\.[\w-]{1,80}-\d+-\d+\.tmp$/.test(f))try{fs.unlinkSync(path.join(dir,f))}catch{}}catch{}
 const file=id=>path.join(dir,id+'.json');
 const unverified=new Set(); // ids committed by rename whose DIRECTORY fsync failed - never confirmed without a re-sync
 let dirFsyncNoted=false,lastDirError=null; // lastDirError: the underlying dir-fsync failure, surfaced for diagnostics (never decides the gate)
 const dirFsync=()=>{
  let dfd=null,stage='open';
  try{dfd=fs.openSync(dir,'r');stage='fsync';fs.fsyncSync(dfd);lastDirError=null}
  catch(e){
   lastDirError=(e&&(e.code||e.message))||String(e);
   let probeOk=false;if(isWin&&e&&(e.code==='EPERM'||e.code==='EACCES')){try{fs.readdirSync(dir);probeOk=true}catch{probeOk=false}} // corroborating evidence: the directory is listable right now
   if(dirFsyncUnsupportedOnWin(isWin,e,stage,probeOk)){if(!dirFsyncNoted){dirFsyncNoted=true;notes.push('dir fsync unsupported on win32 ('+e.code+', stage '+stage+'): rename durability relies on the NTFS journal')}return}
   throw e; // any real dir-fsync failure = durability unproven -> committed-but-unverified
  }finally{if(dfd!=null)try{fs.closeSync(dfd)}catch{}}
 };
 const readRaw=id=>{
  const p=file(id);
  const fl=fs.lstatSync(p,{throwIfNoEntry:false});
  if(!fl)return null;
  if(fl.isSymbolicLink()||!fl.isFile())throw new Error('outbox record not a regular file');
  if(!isWin){
   if(typeof fl.uid==='number'&&fl.uid!==process.getuid())throw new Error('outbox record owned by another uid');
   if((fl.mode&0o777)!==0o600)throw new Error('outbox record mode is not 600');
  }else if(!aclOwnerOnly(p))throw new Error('outbox record ACL is not owner-only'); // verify before EVERY read - an ACL widened after write fails closed
  const rec=JSON.parse(fs.readFileSync(p,'utf8')); // CORRUPT THROWS - fail closed, never catch-all null
  if(!rec||typeof rec!=='object'||Array.isArray(rec))throw new Error('outbox record not an object');
  return rec;
 };
 const envOf=r=>r&&r.envelope!=null?JSON.stringify(r.envelope):null;
 return{
  notes,
  lastError(){return lastDirError}, // diagnostics only - the gate itself stays fail-closed
  async get(id){
   if(closed)throw new Error('outbox closed');
   id=String(id||'');if(!strictId(id))throw new Error('outbox get: bad id');
   return readRaw(id);
  },
  async put(id,record){
   if(closed)throw new Error('outbox closed');
   id=String(id||'');if(!strictId(id))return false;
   if(!record||typeof record!=='object'||Array.isArray(record))return false;
   const prior=readRaw(id); // corrupt prior THROWS - never overwrite what we cannot read
   if(prior){
    if(envOf(prior)!==envOf(record))throw new Error('outbox conflict: envelope under '+id+' is immutable');
    if(prior.receipt!=null&&JSON.stringify(prior.receipt)!==JSON.stringify(record.receipt))throw new Error('outbox conflict: receipt under '+id+' already settled');
    if(JSON.stringify(prior)===JSON.stringify(record)){
     try{dirFsync();unverified.delete(id);return true}catch{return false} // idempotent confirm RE-SYNCS: committed-but-unverified is never promoted without a fresh dir fsync
    }
   }
   const tmp=path.join(dir,'.'+id+'-'+process.pid+'-'+Date.now()+'.tmp');
   let fd=null;
   try{
    const buf=Buffer.from(JSON.stringify(record),'utf8');
    fd=fs.openSync(tmp,'wx',0o600); // exclusive create - a planted tmp is never rewritten
    writeFull(fd,buf); // partial writes loop until the whole UTF-8 buffer lands
    fs.fsyncSync(fd);
    if(isWin&&!aclHarden(tmp,false))throw new Error('record ACL hardening failed'); // SID-exact owner-only BEFORE the record becomes visible under its final name
    fs.closeSync(fd);fd=null;
    fs.renameSync(tmp,file(id)); // atomic same-dir rename; only reached after a fully synced tmp
    try{dirFsync();unverified.delete(id)}catch{unverified.add(id);return false} // committed on disk, durability UNVERIFIED: false, and the idempotent re-put above re-syncs before confirming
    return true;
   }catch{return false}
   finally{if(fd!=null)try{fs.closeSync(fd)}catch{};try{fs.unlinkSync(tmp)}catch{}} // a failed put leaves nothing behind
  },
  // confirm(id): durability gate for the wire. The record must be readable (all fail-closed
  // checks) AND the directory must fsync RIGHT NOW - a reopen cannot know the last sync failed,
  // so confirmation is affirmed at send time, not remembered. False while sync fails: the id is
  // kept, the sender pauses, nothing POSTs.
  async confirm(id){
   if(closed)throw new Error('outbox closed');
   id=String(id||'');if(!strictId(id))return false;
   const prior=readRaw(id);
   if(!prior)return false;
   try{dirFsync();unverified.delete(id);return true}catch{return false}
  },
  close(){release()},
 };
}
module.exports={createFileOutbox,_dirFsyncUnsupportedOnWin:dirFsyncUnsupportedOnWin};
