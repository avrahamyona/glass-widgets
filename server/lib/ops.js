// Named, allowlisted ops for the standalone server ("החיים שלי השרתי").
// Electron-free. Every op: input validation, hard bounds, no generic exec.
const fs=require('fs'),path=require('path'),crypto=require('crypto');

const READ_CAP=512*1024; // hard refusal above this size
const INLINE_CAP=1024; // max file bytes returned INLINE - must fit the ledger's result budget; larger files are metadata-only with an EXPLICIT truncated marker (file transfer is a separate, future op - never a silent round-trip claim)
const FIND_MAX_RESULTS=50, FIND_MAX_DIRS=20000, FIND_TIMEOUT_MS=15000;

// path allowlist: resolved real path must live under one of the configured roots
function underRoots(p,roots){
 let rp;try{rp=fs.realpathSync(p)}catch{return null}
 for(const r of roots){const rr=fs.realpathSync(r);
  if(rp===rr||rp.startsWith(rr.endsWith(path.sep)?rr:rr+path.sep))return rp}
 return null;
}

// bounded recursive filename/content-name search (name match only in the skeleton)
function findFiles(data,ctx){
 const q=String(data.query||'').trim();
 if(!q||q.length>200)return {ok:false,error:'bad_query'};
 let roots=ctx.roots.slice(0,10);
 if(Array.isArray(data.roots)&&data.roots.length){ // a sender may NARROW the scan to subdirs under the configured roots - NEVER widen it
  roots=data.roots.slice(0,10).filter(r=>underRoots(String(r||''),ctx.roots)!==null);
  if(!roots.length)return {ok:false,error:'outside_roots'};
 }
 const lim=Math.min(Math.max(+(data.limit||FIND_MAX_RESULTS),1),FIND_MAX_RESULTS);
 const needle=q.toLowerCase(),out=[];let seen=0;const t0=Date.now();
 const walk=d=>{
  if(out.length>=lim||seen>FIND_MAX_DIRS||Date.now()-t0>FIND_TIMEOUT_MS)return;
  let ents;try{ents=fs.readdirSync(d,{withFileTypes:true})}catch{return}
  for(const e of ents){
   if(out.length>=lim||Date.now()-t0>FIND_TIMEOUT_MS)return;
   const p=path.join(d,e.name);
   if(e.isDirectory()){seen++;if(!e.name.startsWith('.')&&e.name!=='node_modules')walk(p)}
   else if(e.name.toLowerCase().includes(needle)){
    let st=null;try{st=fs.statSync(p)}catch{}
    out.push({path:p,size:st?st.size:0,mtime:st?+st.mtime:0});
   }}};
 for(const r of roots){try{if(fs.statSync(r).isDirectory())walk(r)}catch{}}
 return {ok:true,result:{matches:out.slice(0,lim),truncated:out.length>=lim}};
}

function readFile(data,ctx){
 const p=String(data.path||'');
 if(!p||p.length>1000)return {ok:false,error:'bad_path'};
 const rp=underRoots(p,ctx.roots);
 if(!rp)return {ok:false,error:'outside_roots'};
 let st;try{st=fs.statSync(rp)}catch{return {ok:false,error:'not_found'}}
 if(!st.isFile())return {ok:false,error:'not_a_file'};
 if(st.size>READ_CAP)return {ok:false,error:'too_large',size:st.size};
 const buf=fs.readFileSync(rp);
 const result={path:rp,size:st.size,sha256:crypto.createHash('sha256').update(buf).digest('hex')};
 if(buf.length<=INLINE_CAP){result.content_base64=buf.toString('base64');result.truncated=false}
 else{result.content_base64=buf.subarray(0,INLINE_CAP).toString('base64');result.truncated=true;result.inline_cap=INLINE_CAP;result.note='content cut at '+INLINE_CAP+' bytes to fit the ledger - full file transfer is a separate op'}
 return {ok:true,result};
}

// closed kind allowlist - the skeleton's op registry (no run_command, no generic execute).
// null-prototype object: prototype names (constructor, toString, ...) are NOT ops.
const OPS=Object.assign(Object.create(null),{find_files:findFiles,read_file:readFile});
module.exports={OPS,READ_CAP};
