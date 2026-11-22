'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),manifest=JSON.parse(fs.readFileSync(path.join(__dirname,'integration-hashes.json'),'utf8'));
assert.equal(manifest.version,1);assert(Array.isArray(manifest.files)&&manifest.files.length>0);
const seen=new Set();
for(const record of manifest.files){
 assert(typeof record.path==='string'&&!record.path.startsWith('/')&&!record.path.split('/').includes('..')&&!seen.has(record.path));seen.add(record.path);
 const file=path.join(root,record.path),st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink());
 const bytes=fs.readFileSync(file);assert.equal(bytes.length,record.bytes,record.path+' byte count changed');
 assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),record.sha256,record.path+' source bytes changed');
}
console.log(JSON.stringify({reviewedFiles:seen.size,exactBytes:true,nativeRuntimeProof:false,installation:false}));
