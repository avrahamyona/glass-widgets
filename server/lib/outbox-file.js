// Production sender outbox: durable, atomic, fail-closed. One JSON file per command id under a
// private dir. Contract:
//  DURABILITY: tmp(exclusive wx, mode 600) -> full-buffer writeSync LOOP -> fsync(file) ->
//  atomic same-dir rename -> fsync(DIRECTORY) so the rename itself survives power loss.
//  A failed write/fsync/rename returns false and removes the tmp: the PREVIOUS final record
//  stays intact. (On win32, where libuv cannot fsync a directory handle, the dir-fsync step is
//  recorded in outbox.notes as unsupported and the rename relies on the NTFS journal - every
//  other platform fails closed.)
//  FAIL-CLOSED READS: missing = null; CORRUPT / non-object / symlink / non-regular THROWS.
//  CONCURRENCY: a single-writer lease (.outbox.lock, wx-create, pid+host) is held for the
//  instance's lifetime; a live same-host holder blocks any second opener, a dead-pid lock is
//  reclaimed. tmp sweep runs ONLY after the lease is held. put is an immutable-envelope CAS:
//  the serialized envelope under an id can never change (conflict throws), receipt/at may only
//  advance null->set. close() releases the lease; get/put after close throw.
//  PRIVACY: the dir must not be a symlink; on POSIX it is enforced to mode 700 + owner uid,
//  files are mode 600. On win32 POSIX modes are meaningless, so the dir must live under the
//  user profile (os.homedir, user-only ACL by default) and a note is recorded - SID-exact ACL
//  hardening on Windows is the installer/boot-fixture's job, not this module's claim.
const fs=require('fs'),path=require('path'),os=require('os');
const{strictId}=require('../../src/lib/command-contract'); // the ledger's id shape - also the filename boundary (no traversal)
function createFileOutbox(dir,opts){
 opts=opts||{};
 if(!dir)throw new Error('outbox needs a dir');
 const isWin=process.platform==='win32';
 const notes=[];
 // --- privacy boundary: no symlink dir, enforced mode/owner on POSIX, profile-rooted on win32 ---
 const lst=fs.lstatSync(dir,{throwIfNoEntry:false});
 if(lst&&lst.isSymbolicLink())throw new Error('outbox dir is a symlink');
 if(!lst)fs.mkdirSync(dir,{recursive:true,mode:0o700});
 const st=fs.lstatSync(dir);
 if(st.isSymbolicLink())throw new Error('outbox dir is a symlink');
 if(!st.isDirectory())throw new Error('outbox dir is not a directory');
 if(isWin){
  const home=path.resolve(os.homedir()),real=path.resolve(dir);
  if(real!==home&&!real.startsWith(home+path.sep))throw new Error('outbox dir must live under the user profile on Windows');
  notes.push('win32: POSIX modes n/a; privacy relies on the user-profile ACL (installer hardens SID-exact ACLs)');
 }else{
  if(typeof st.uid==='number'&&st.uid!==process.getuid())throw new Error('outbox dir owned by another uid');
  if((st.mode&0o777)!==0o700){fs.chmodSync(dir,0o700);const st2=fs.lstatSync(dir);if((st2.mode&0o777)!==0o700)throw new Error('outbox dir mode not 700 after chmod');}
 }
 // --- single-writer lease ---
 const lockPath=path.join(dir,'.outbox.lock');
 const holder=()=>{try{return JSON.parse(fs.readFileSync(lockPath,'utf8'))}catch{return null}};
 const alive=h=>{try{process.kill(h.pid,0);return true}catch(e){return e&&e.code==='EPERM'}};
 const acquire=()=>{
  try{
   const fd=fs.openSync(lockPath,'wx',0o600);
   fs.writeSync(fd,JSON.stringify({pid:process.pid,host:os.hostname(),at:Date.now()}));
   fs.closeSync(fd);
  }catch(e){
   if(!(e&&e.code==='EEXIST'))throw e;
   const h=holder();
   if(h&&h.host===os.hostname()&&typeof h.pid==='number'&&!alive(h)){try{fs.unlinkSync(lockPath)}catch{};acquire();return} // dead-pid reclaim, same host only
   throw new Error('outbox lease held by '+(h?('pid '+h.pid+' on '+h.host):'an unreadable lock'));
  }
 };
 acquire();
 let closed=false;
 const release=()=>{if(closed)return;closed=true;process.removeListener('exit',release);try{fs.unlinkSync(lockPath)}catch{}};
 process.once('exit',release); // best-effort on crash-adjacent exits; a hard kill leaves a dead-pid lock that the next opener reclaims
 // --- stale tmp sweep: only now, only under the lease, only our tmp shape ---
 try{for(const f of fs.readdirSync(dir))if(/^\.[\w-]{1,80}-\d+-\d+\.tmp$/.test(f))try{fs.unlinkSync(path.join(dir,f))}catch{}}catch{}
 const file=id=>path.join(dir,id+'.json');
 const dirFsync=()=>{
  let dfd=null;
  try{dfd=fs.openSync(dir,'r');fs.fsyncSync(dfd)}
  catch(e){
   if(isWin&&e&&(e.code==='EINVAL'||e.code==='EBADF'||e.code==='ENOTSUP')){notes.push('dir fsync unsupported on win32 ('+e.code+'): rename durability relies on the NTFS journal');return}
   throw e; // any real dir-fsync failure = durability unproven -> put fails closed
  }finally{if(dfd!=null)try{fs.closeSync(dfd)}catch{}}
 };
 const readRaw=id=>{
  const p=file(id);
  const fl=fs.lstatSync(p,{throwIfNoEntry:false});
  if(!fl)return null;
  if(fl.isSymbolicLink()||!fl.isFile())throw new Error('outbox record not a regular file');
  const rec=JSON.parse(fs.readFileSync(p,'utf8')); // CORRUPT THROWS - fail closed, never catch-all null
  if(!rec||typeof rec!=='object'||Array.isArray(rec))throw new Error('outbox record not an object');
  return rec;
 };
 const envOf=r=>r&&r.envelope!=null?JSON.stringify(r.envelope):null;
 return{
  notes,
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
    if(JSON.stringify(prior)===JSON.stringify(record))return true; // idempotent re-put
   }
   const tmp=path.join(dir,'.'+id+'-'+process.pid+'-'+Date.now()+'.tmp');
   let fd=null;
   try{
    const buf=Buffer.from(JSON.stringify(record),'utf8');
    fd=fs.openSync(tmp,'wx',0o600); // exclusive create - a planted tmp is never rewritten
    let off=0;
    while(off<buf.length){const n=fs.writeSync(fd,buf,off,buf.length-off);if(!(n>0))throw new Error('short write');off+=n} // partial writes loop until the whole UTF-8 buffer lands
    fs.fsyncSync(fd);fs.closeSync(fd);fd=null;
    fs.renameSync(tmp,file(id)); // atomic same-dir rename; only reached after a fully synced tmp
    dirFsync(); // the rename itself must survive power loss
    return true;
   }catch{return false}
   finally{if(fd!=null)try{fs.closeSync(fd)}catch{};try{fs.unlinkSync(tmp)}catch{}} // a failed put leaves nothing behind
  },
  close(){release()},
 };
}
module.exports={createFileOutbox};
