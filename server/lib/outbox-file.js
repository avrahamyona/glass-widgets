// Production sender outbox: durable, atomic, fail-closed. One JSON file per command id under a
// private dir. Writes go tmp(exclusive) -> fsync -> atomic rename; a crash can leave a stale tmp,
// never a torn final record. Reads FAIL CLOSED: a missing record is null, but a CORRUPT record
// THROWS - the sender turns that into outbox_read_failed (unknown, manual reconcile), never a
// silent re-send. This is the real store behind the retry reconciliation proven in the fixtures.
const fs=require('fs'),path=require('path');
const{strictId}=require('../../src/lib/command-contract'); // the ledger's id shape - also the filename boundary (no traversal)
function createFileOutbox(dir){
 if(!dir)throw new Error('outbox needs a dir');
 fs.mkdirSync(dir,{recursive:true,mode:0o700});
 const file=id=>path.join(dir,id+'.json');
 const cleanTmps=()=>{try{for(const f of fs.readdirSync(dir))if(f.endsWith('.tmp'))try{fs.unlinkSync(path.join(dir,f))}catch{}}catch{}};
 cleanTmps(); // crash residue from a PREVIOUS run never accumulates
 return{
  async get(id){
   id=String(id||'');if(!strictId(id))throw new Error('outbox get: bad id');
   let raw;try{raw=fs.readFileSync(file(id),'utf8')}catch(e){if(e&&e.code==='ENOENT')return null;throw e}
   const rec=JSON.parse(raw); // CORRUPT THROWS - fail closed, never catch-all null
   if(!rec||typeof rec!=='object'||Array.isArray(rec))throw new Error('outbox record not an object');
   return rec;
  },
  async put(id,record){
   id=String(id||'');if(!strictId(id))return false;
   if(!record||typeof record!=='object'||Array.isArray(record))return false;
   const tmp=path.join(dir,'.'+id+'-'+process.pid+'-'+Date.now()+'.tmp');
   let fd=null;
   try{
    const raw=JSON.stringify(record);
    fd=fs.openSync(tmp,'wx',0o600); // exclusive create - a planted tmp is never rewritten
    fs.writeSync(fd,raw);fs.fsyncSync(fd);fs.closeSync(fd);fd=null;
    fs.renameSync(tmp,file(id)); // atomic same-dir rename
    return true;
   }catch{return false}
   finally{if(fd!=null)try{fs.closeSync(fd)}catch{};try{fs.unlinkSync(tmp)}catch{}} // a failed put leaves nothing behind
  },
 };
}
module.exports={createFileOutbox};
