// Production outbox (server/lib/outbox-file.js): durability, atomicity, fail-closed, lease, privacy.
// Fault injection patches the SHARED fs module object (outbox-file requires the same instance);
// every patch is scoped to one put and restored in finally.
const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path');
const{createFileOutbox}=require('../server/lib/outbox-file');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gw-outbox-u-'));
const rec=(n)=>({envelope:{id:'cmd-'+n,kind:'find_files'},receipt:null,at:n});
const patched=async(obj,key,fn,body)=>{const orig=obj[key];obj[key]=fn;try{return await body()}finally{obj[key]=orig}}; // await the body: the patch must outlive every fs call inside it
const realOpen=fs.openSync;
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
 fs.writeFileSync(path.join(dir,'cmd-bad.json'),'{not json',{mode:0o600}); // well-formed mode, corrupt CONTENT: tests the JSON gate, not the mode gate
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
 // FAULT INJECTION 5: POST-RENAME dir fsync failure - committed-but-unverified: the record lands
 // (get returns it), put=false, and an idempotent re-put is NOT confirmed until a fresh dir fsync succeeds
 await patched(fs,'openSync',(p,flags,mode)=>{
  if(p===dir&&flags==='r')throw Object.assign(new Error('dir sync unavailable'),{code:'EIO'});
  return realOpen(p,flags,mode);
 },async()=>{
  assert((await b4.put('cmd-6',rec(6)))===false,'dir-fsync failure refuses the put');
  assert((await b4.get('cmd-6')).envelope.id==='cmd-6','record committed on disk (readable) but unverified');
  assert((await b4.put('cmd-6',rec(6)))===false,'idempotent re-put still unconfirmed while dir fsync fails');
 });
 assert((await b4.put('cmd-6',rec(6)))===true,'idempotent re-put confirms after dir fsync heals');
 // confirm(): the durability gate the sender checks before the wire
 assert((await b4.confirm('cmd-absent'))===false,'confirm on a missing record is false');
 assert((await b4.confirm('cmd-2'))===true,'confirm on a healthy record is true');
 await patched(fs,'openSync',(p,f,m)=>{if(p===dir&&f==='r')throw Object.assign(new Error('x'),{code:'EIO'});return realOpen(p,f,m)},async()=>{
  assert((await b4.confirm('cmd-2'))===false,'confirm false while dir fsync fails');
 });
 // WIN32 DIR-FSYNC LIMITATION POLICY: EPERM/EACCES (newer Node dir-open) and EINVAL/EBADF/ENOTSUP
 // (older fsync) all take the NTFS-journal note path on win32 ONLY; any other code, and ANY code
 // off-win32, fails closed.
 {const{_dirFsyncUnsupportedOnWin:unsup}=require('../src/lib/durable-store.js');
  for(const c of['EPERM','EACCES','EINVAL','EBADF','ENOTSUP'])assert(unsup(true,{code:c})===true,'win32 dir-fsync code '+c+' takes the note path');
  assert(unsup(true,{code:'EIO'})===false,'EIO is a REAL dir-fsync failure even on win32 - fail closed');
  assert(unsup(false,{code:'EPERM'})===false,'EPERM off-win32 fails closed');}
 // POSIX READ CHECKS: a record with widened mode fails closed on read
 if(process.platform!=='win32'){
  fs.chmodSync(path.join(dir,'cmd-6.json'),0o644);
  await assert.rejects(()=>b4.get('cmd-6'),/mode is not 600/,'widened record mode fails closed on read');
  fs.chmodSync(path.join(dir,'cmd-6.json'),0o600);
 }
 // CONCURRENT RECLAIM (process level): a dead-pid lock + two parallel openers -> EXACTLY ONE wins
 b4.close();
 fs.writeFileSync(path.join(dir,'.outbox.lock'),JSON.stringify({pid:99999999,host:os.hostname(),at:1}));
 const child=()=>{const{spawn}=require('child_process');return new Promise(res=>{
  const c=spawn(process.execPath,['-e','try{const b=require('+JSON.stringify(require.resolve('../server/lib/outbox-file'))+').createFileOutbox(process.argv[1]);console.log("OK");setTimeout(()=>process.exit(0),400)}catch(e){console.log("REFUSED")}',dir],{stdio:['ignore','pipe','ignore']});
  let out='';c.stdout.on('data',d=>out+=d);c.on('close',()=>res(out.trim()));})};
 const[rA,rB]=await Promise.all([child(),child()]);
 assert.strictEqual([rA,rB].filter(x=>x==='OK').length,1,'exactly one concurrent reclaimer wins: '+rA+','+rB);
 assert.strictEqual([rA,rB].filter(x=>x==='REFUSED').length,1,'the loser is refused: '+rA+','+rB);
 // a LIVE reclaim guard blocks openers; a STALE guard (dead pid) is cleared by the next reclaimer
 fs.writeFileSync(path.join(dir,'.outbox.lock'),JSON.stringify({pid:99999999,host:os.hostname(),at:1}));
 fs.mkdirSync(path.join(dir,'.outbox.reclaim'),{recursive:true});
 fs.writeFileSync(path.join(dir,'.outbox.reclaim','pid'),JSON.stringify({pid:process.pid,host:os.hostname()})); // live (us) as stand-in live reclaimer
 assert.throws(()=>createFileOutbox(dir),/reclaim in progress/,'live reclaim guard blocks');
 fs.writeFileSync(path.join(dir,'.outbox.reclaim','pid'),JSON.stringify({pid:99999999,host:os.hostname()})); // stale guard
 const b5=createFileOutbox(dir);
 assert((await b5.get('cmd-6')).envelope.id==='cmd-6','stale guard cleared, dead lock reclaimed, records intact');
 b5.close();
 // guard publish gap: a FRESH pidless guard is a LIVE reclaimer (refuse); only OLD residue is clearable
 b4.close();
 fs.writeFileSync(path.join(dir,'.outbox.lock'),JSON.stringify({pid:99999999,host:os.hostname(),at:1}));
 fs.mkdirSync(path.join(dir,'.outbox.reclaim')); // pid never published
 assert.throws(()=>createFileOutbox(dir),/unpublished guard/,'fresh pidless guard is LIVE - refused');
 fs.utimesSync(path.join(dir,'.outbox.reclaim'),new Date(Date.now()-120000),new Date(Date.now()-120000));
 const b6=createFileOutbox(dir);
 assert((await b6.get('cmd-2')).envelope.id==='cmd-2','old pidless guard is crash residue - cleared, records intact');
 b6.close();
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
 // in-process lifecycle: create -> close -> create on the SAME dir with the SAME live pid must work
// (the agent stop() path closes the journal before any restart; a stale same-pid lock would refuse)
{const d=fs.mkdtempSync('/tmp/gw-outbox-life-');
 const b1=createFileOutbox(d);await b1.put('life1',{envelope:{x:1},receipt:null});b1.close();
 const b2=createFileOutbox(d);
 assert((await b2.get('life1'))&&JSON.stringify((await b2.get('life1')).envelope)==='{"x":1}','record readable after close+reopen in the same process');
 assert(await b2.put('life2',{envelope:{y:2},receipt:null})===true,'write works after close+reopen in the same process');
 b2.close();
 const b3=createFileOutbox(d);b3.close(); // a third cycle: no residue blocks re-acquire
 console.log('OUTBOX-LIFECYCLE: PASS')}
console.log('SENDER-OUTBOX-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
