// Production outbox (server/lib/outbox-file.js): durability, atomicity, fail-closed, lease, privacy.
// Fault injection patches the SHARED fs module object (outbox-file requires the same instance);
// every patch is scoped to one put and restored in finally.
const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path');
const{createFileOutbox}=require('../server/lib/outbox-file');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gw-outbox-u-'));
const rec=(n)=>({envelope:{id:'cmd-'+n,kind:'find_files'},receipt:null,at:n});
const patched=(obj,key,fn,body)=>{const orig=obj[key];obj[key]=fn;try{return body()}finally{obj[key]=orig}};
(async()=>{
 // roundtrip + durability across instances (a sender restart closes, re-opens, sees the SAME record)
 const b1=createFileOutbox(dir);
 assert(await b1.put('cmd-1',rec(1))===true,'put ok');
 b1.close();
 const b2=createFileOutbox(dir); // restart
 const r=await b2.get('cmd-1');
 assert(r&&r.envelope&&r.envelope.id==='cmd-1','record survives a restart');
 assert((await b2.get('cmd-absent'))===null,'missing record is null');
 // CORRUPT -> THROWS (fail closed: never a silent null that would allow a blind re-send)
 fs.writeFileSync(path.join(dir,'cmd-bad.json'),'{not json');
 await assert.rejects(()=>b2.get('cmd-bad'),/JSON/,'corrupt record throws');
 // id boundary: traversal and proto names refused
 assert((await b2.put('../evil',{a:1}))===false,'traversal id refused on put');
 await assert.rejects(()=>b2.get('../evil'),'traversal id refused on get');
 assert((await b2.put('__proto__',{a:1}))===false,'proto id refused');
 // immutable-envelope CAS: same id with a DIFFERENT envelope throws; receipt may only advance null->set
 await assert.rejects(()=>b2.put('cmd-1',{envelope:{id:'cmd-1',kind:'OTHER'},receipt:null,at:9}),/immutable/,'envelope under an id is immutable');
 assert((await b2.put('cmd-1',{envelope:{id:'cmd-1',kind:'find_files'},receipt:{status:'ok'},at:2}))===true,'receipt advances null->set');
 assert((await b2.put('cmd-1',{envelope:{id:'cmd-1',kind:'find_files'},receipt:{status:'ok'},at:2}))===true,'idempotent re-put');
 await assert.rejects(()=>b2.put('cmd-1',{envelope:{id:'cmd-1',kind:'find_files'},receipt:{status:'DIFFERENT'},at:3}),/settled/,'settled receipt cannot change');
 // single-writer lease: a second live opener is refused while b2 holds the lock
 assert.throws(()=>createFileOutbox(dir),/lease held by pid/,'second live opener refused');
 b2.close();
 await assert.rejects(()=>b2.get('cmd-1'),/closed/,'get after close throws');
 await assert.rejects(()=>b2.put('cmd-2',rec(2)),/closed/,'put after close throws');
 // dead-pid lock from a crashed holder is reclaimed (same host)
 fs.writeFileSync(path.join(dir,'.outbox.lock'),JSON.stringify({pid:99999999,host:os.hostname(),at:1}));
 const b3=createFileOutbox(dir);
 assert((await b3.get('cmd-1')).envelope.id==='cmd-1','dead-pid lock reclaimed, records intact');
 // atomicity: a stale tmp from a crash does not shadow or corrupt the final record; sweep runs under the lease
 fs.writeFileSync(path.join(dir,'.cmd-9-1-1.tmp'),'{"partial"');
 fs.writeFileSync(path.join(dir,'other.tmp'),'{"not-ours"}'); // foreign tmp shape: never swept
 b3.close();
 const b4=createFileOutbox(dir);
 assert(!fs.existsSync(path.join(dir,'.cmd-9-1-1.tmp')),'stale crash tmp swept on open');
 assert(fs.existsSync(path.join(dir,'other.tmp')),'foreign tmp left alone');
 assert((await b4.get('cmd-9'))===null,'swept tmp never becomes a record');
 fs.unlinkSync(path.join(dir,'other.tmp'));
 // failed put (invalid record) returns false and leaves nothing behind
 assert((await b4.put('cmd-10',null))===false,'invalid record refused');
 assert((await b4.get('cmd-10'))===null,'failed put leaves no record');
 // FAULT INJECTION 1: short writes - writeSync lands 3 bytes per call; the loop must still deliver the whole buffer
 await b4.put('cmd-2',rec(2));
 const realWrite=fs.writeSync;
 await patched(fs,'writeSync',(fd,buf,off,len)=>realWrite(fd,buf,off,Math.min(3,len)),async()=>{ // lands, but 3 bytes at a time
  assert((await b4.put('cmd-2',{envelope:{id:'cmd-2',kind:'find_files'},receipt:{status:'ok'},at:22}))===true,'short-write put completes');
 });
 const r2=await b4.get('cmd-2');
 assert(r2.receipt&&r2.receipt.status==='ok'&&r2.at===22,'short-write content is whole and valid JSON');
 // FAULT INJECTION 2: writeSync returns 0 - put fails false and the PREVIOUS record survives byte-exact
 const before=fs.readFileSync(path.join(dir,'cmd-2.json'),'utf8');
 await patched(fs,'writeSync',()=>0,async()=>{
  assert((await b4.put('cmd-3',rec(3)))===false,'zero-write put refuses');
 });
 assert(fs.readFileSync(path.join(dir,'cmd-2.json'),'utf8')===before,'previous record byte-exact after zero-write');
 // FAULT INJECTION 3: file fsync throws (first fsyncSync call) - put false, previous record survives
 let fsyncCalls=0;
 const realFsync=fs.fsyncSync;
 await patched(fs,'fsyncSync',(fd)=>{fsyncCalls++;if(fsyncCalls===1)throw new Error('disk sync failed');return realFsync(fd)},async()=>{
  assert((await b4.put('cmd-4',rec(4)))===false,'fsync failure refuses the put');
 });
 assert((await b4.get('cmd-4'))===null,'fsync-failed record never installed');
 assert(fs.readFileSync(path.join(dir,'cmd-2.json'),'utf8')===before,'previous record byte-exact after fsync failure');
 // FAULT INJECTION 4: rename throws - put false, tmp cleaned, previous record survives
 await patched(fs,'renameSync',()=>{throw new Error('rename failed')},async()=>{
  assert((await b4.put('cmd-5',rec(5)))===false,'rename failure refuses the put');
 });
 assert((await b4.get('cmd-5'))===null,'rename-failed record never installed');
 assert(fs.readdirSync(dir).filter(f=>/\.tmp$/.test(f)&&f!=='other.tmp').length===0,'no tmp residue after failures');
 // PRIVACY (POSIX): a pre-existing 0755 dir is enforced to 700 on open; a symlink dir is refused
 if(process.platform!=='win32'){
  const lax=fs.mkdtempSync(path.join(os.tmpdir(),'gw-outbox-lax-'));
  fs.chmodSync(lax,0o755);
  const bl=createFileOutbox(lax);
  assert.strictEqual(fs.lstatSync(lax).mode&0o777,0o700,'pre-existing 0755 dir enforced to 700');
  assert.strictEqual(fs.lstatSync(lax).uid,process.getuid(),'dir owned by this uid');
  await bl.put('x',{a:1});
  assert.strictEqual(fs.lstatSync(path.join(lax,'x.json')).mode&0o777,0o600,'record file mode 600');
  bl.close();
  const real=fs.mkdtempSync(path.join(os.tmpdir(),'gw-outbox-real-'));
  const link=path.join(os.tmpdir(),'gw-outbox-link-'+process.pid);
  fs.symlinkSync(real,link);
  assert.throws(()=>createFileOutbox(link),/symlink/,'symlink dir refused');
  fs.unlinkSync(link);
  fs.rmSync(lax,{recursive:true,force:true});fs.rmSync(real,{recursive:true,force:true});
 }
 b4.close();
 fs.rmSync(dir,{recursive:true,force:true});
 console.log('SENDER-OUTBOX-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
