// Production outbox (server/lib/outbox-file.js): durability, atomicity, fail-closed semantics.
const assert=require('assert'),fs=require('fs'),os=require('os'),path=require('path');
const{createFileOutbox}=require('../server/lib/outbox-file');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gw-outbox-u-'));
(async()=>{
 // roundtrip + durability across instances (a sender restart sees the SAME record)
 const b1=createFileOutbox(dir);
 assert(await b1.put('cmd-1',{envelope:{id:'cmd-1',kind:'find_files'},receipt:null,at:1})===true,'put ok');
 const b2=createFileOutbox(dir); // restart
 const r=await b2.get('cmd-1');
 assert(r&&r.envelope&&r.envelope.id==='cmd-1','record survives a restart');
 // missing -> null (NOT an error)
 assert((await b2.get('cmd-absent'))===null,'missing record is null');
 // CORRUPT -> THROWS (fail closed: never a silent null that would allow a blind re-send)
 fs.writeFileSync(path.join(dir,'cmd-bad.json'),'{not json');
 await assert.rejects(()=>b2.get('cmd-bad'),/JSON/,'corrupt record throws');
 // a corrupt record must NOT be overwritten by a blind put pretending it never existed
 // (the sender's prepare() gets the throw BEFORE any put - covered in sender-client-unit)
 // id boundary: traversal and proto names refused
 assert((await b2.put('../evil',{a:1}))===false,'traversal id refused on put');
 await assert.rejects(()=>b2.get('../evil'),'traversal id refused on get');
 assert((await b2.put('__proto__',{a:1}))===false,'proto id refused');
 // atomicity: a stale tmp from a crash does not shadow or corrupt the final record; sweep on open
 fs.writeFileSync(path.join(dir,'.cmd-9-1-1.tmp'),'{"partial"');
 const b3=createFileOutbox(dir);
 assert(!fs.existsSync(path.join(dir,'.cmd-9-1-1.tmp')),'stale crash tmp swept on open');
 assert((await b3.get('cmd-9'))===null,'swept tmp never becomes a record');
 // failed put (unwritable record) returns false and leaves nothing behind
 assert((await b3.put('cmd-10',null))===false,'invalid record refused');
 assert((await b3.get('cmd-10'))===null,'failed put leaves no record');
 assert(fs.readdirSync(dir).filter(f=>f.endsWith('.tmp')).length===0,'no tmp residue after failures');
 fs.rmSync(dir,{recursive:true,force:true});
 console.log('SENDER-OUTBOX-UNIT: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
