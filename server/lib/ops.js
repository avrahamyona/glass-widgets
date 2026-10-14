// Named, allowlisted ops for the standalone server ("החיים שלי השרתי").
// Electron-free. Every op: input validation, hard bounds, signed-envelope gated at intake.
const fs=require('fs'),path=require('path'),crypto=require('crypto'),os=require('os');
const{spawn}=require('child_process');

const{RESULT_CAP}=require('../../src/lib/ledger');
const READ_CAP=512*1024; // hard refusal above this size
const WRITE_CAP=1024*1024; // hard bound per write_file call (create/append only - never overwrite, never delete)
const INLINE_CAP=1024; // max file bytes returned inline - NEVER a promise: the real budget is dynamic (below)
// dynamic inline budget: the result JSON must fit the ledger's RESULT_CAP TOGETHER with the
// path, sha256 and the truncation descriptor. base64 inflates bytes 4/3; when the computed
// budget cannot hold a useful prefix we return a metadata-only descriptor instead - the
// explicit truncation marker must survive the ledger cap, never collapse into a generic stub.
function inlineBytes(rp){
 const overhead=Buffer.byteLength(JSON.stringify({path:rp,size:0,sha256:'x'.repeat(64),truncated:true,inline_cap:0,note:'x'.repeat(120)}));
 const budget=RESULT_CAP-overhead-64; // 64B slack for JSON structure drift
 return Math.max(0,Math.min(INLINE_CAP,Math.floor(budget*3/4)));
}
const FIND_MAX_RESULTS=50, FIND_MAX_DIRS=20000, FIND_TIMEOUT_MS=15000;

// --- access scope: configured roots MINUS an always-on denylist. Secrets never leave the PC. ---
// Two layers, both fail closed and not removable by config (a config `deny` array can only ADD):
//  * prefix denies: the server's own data dir (device private key, config with the mailer
//    app-password + token, ledger, tunnel state) and the user's key dirs (.ssh/.gnupg)
//  * basename denies: browser credential stores and common private-key filenames, ANYWHERE
// Denied paths fail with the same 'outside_roots' refusal as out-of-root paths - no oracle.
const DENY_BASENAMES=new Set(['login data','login data-journal','web data','cookies','cookies-journal','key3.db','key4.db','logins.json','id_rsa','id_dsa','id_ecdsa','id_ed25519']);
function defaultDenyDirs(dataDir){
 const home=os.homedir();
 return [dataDir,path.join(home,'.ssh'),path.join(home,'.gnupg')];
}
function resolveDeny(denyDirs){
 const out=[];
 for(const d of denyDirs||[]){let rr;try{rr=fs.realpathSync(String(d))}catch{continue}out.push(rr)}
 return out;
}
function deniedPath(rp,denyPrefixes){
 for(const rr of denyPrefixes){if(rp===rr||rp.startsWith(rr.endsWith(path.sep)?rr:rr+path.sep))return true}
 return false;
}
function deniedName(p){return DENY_BASENAMES.has(path.basename(String(p)).toLowerCase())}

// path allowlist: resolved real path must live under one of the configured roots and outside
// every deny prefix. realpath on the TARGET resolves symlinks before the check (fail closed).
function underRoots(p,roots,denyDirs){
 if(deniedName(p))return null;
 let rp;try{rp=fs.realpathSync(p)}catch{return null}
 const denyP=resolveDeny(denyDirs);
 if(deniedPath(rp,denyP))return null;
 for(const r of roots){const rr=fs.realpathSync(r);
  if(rp===rr||rp.startsWith(rr.endsWith(path.sep)?rr:rr+path.sep))return rp}
 return null;
}

// write targets do not exist yet (create) or may (append): realpath the PARENT instead,
// then re-attach the basename. 'wx' makes symlink-preplant overwrite impossible.
function writeTarget(p,roots,denyDirs){
 if(deniedName(p))return null;
 const dirPart=path.dirname(p),base=path.basename(p);
 if(!base||base===p)return null;
 const rpDir=underRoots(dirPart,roots,denyDirs);
 if(!rpDir)return null;
 return path.join(rpDir,base);
}

// bounded recursive filename/content-name search (name match only in the skeleton)
function findFiles(data,ctx){
 const q=String(data.query||'').trim();
 if(!q||q.length>200)return {ok:false,error:'bad_query'};
 let roots=ctx.roots.slice(0,10);
 if(Array.isArray(data.roots)&&data.roots.length){ // a sender may NARROW the scan to subdirs under the configured roots - NEVER widen it
  roots=data.roots.slice(0,10).filter(r=>underRoots(String(r||''),ctx.roots,ctx.deny)!==null);
  if(!roots.length)return {ok:false,error:'outside_roots'};
 }
 const denyP=resolveDeny(ctx.deny);
 const lim=Math.min(Math.max(+(data.limit||FIND_MAX_RESULTS),1),FIND_MAX_RESULTS);
 const needle=q.toLowerCase(),out=[];let seen=0;const t0=Date.now();
 const walk=d=>{
  if(out.length>=lim||seen>FIND_MAX_DIRS||Date.now()-t0>FIND_TIMEOUT_MS)return;
  let ents;try{ents=fs.readdirSync(d,{withFileTypes:true})}catch{return}
  for(const e of ents){
   if(out.length>=lim||Date.now()-t0>FIND_TIMEOUT_MS)return;
   if(deniedName(e.name))continue; // denied basenames are invisible to the scan
   const p=path.join(d,e.name);
   if(e.isDirectory()){seen++;if(deniedPath(p,denyP))continue;if(!e.name.startsWith('.')&&e.name!=='node_modules')walk(p)}
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
 const rp=underRoots(p,ctx.roots,ctx.deny);
 if(!rp)return {ok:false,error:'outside_roots'};
 let st;try{st=fs.statSync(rp)}catch{return {ok:false,error:'not_found'}}
 if(!st.isFile())return {ok:false,error:'not_a_file'};
 if(st.size>READ_CAP)return {ok:false,error:'too_large',size:st.size};
 const buf=fs.readFileSync(rp);
 const result={path:rp,size:st.size,sha256:crypto.createHash('sha256').update(buf).digest('hex')};
 const cap=inlineBytes(rp);
 if(buf.length<=cap){result.content_base64=buf.toString('base64');result.truncated=false}
 else if(cap>=128){result.content_base64=buf.subarray(0,cap).toString('base64');result.truncated=true;result.inline_cap=cap;result.note='prefix of '+cap+' bytes (dynamic ledger budget) - full file transfer is a separate op'}
 else{result.truncated=true;result.inline_cap=0;result.note='no inline budget at this path length - metadata only; full file transfer is a separate op'}
 return {ok:true,result};
}

// write_file: create (default, 'wx' - REFUSES to overwrite anything that exists, including a
// planted symlink) or append. No overwrite mode, no delete - by the user's standing constraint.
function writeFile(data,ctx){
 const p=String(data.path||'');
 if(!p||p.length>1000)return {ok:false,error:'bad_path'};
 const mode=data.mode===undefined?'create':String(data.mode);
 if(mode!=='create'&&mode!=='append')return {ok:false,error:'bad_mode'};
 const buf=Buffer.from(String(data.content_base64||''),'base64');
 if(buf.length>WRITE_CAP)return {ok:false,error:'too_large',size:buf.length};
 const tp=writeTarget(p,ctx.roots,ctx.deny);
 if(!tp)return {ok:false,error:'outside_roots'};
 try{
  if(mode==='create')fs.writeFileSync(tp,buf,{flag:'wx',mode:0o600});
  else fs.appendFileSync(tp,buf);
 }catch(e){
  if(e&&e.code==='EEXIST')return {ok:false,error:'exists'};
  return {ok:false,error:'write_failed'};
 }
 return {ok:true,result:{path:tp,bytes:buf.length,sha256:crypto.createHash('sha256').update(buf).digest('hex'),mode}};
}


// --- stage 2: process launch (whole-PC operation, user-approved 2026-10-14) ---
// spawn with an args ARRAY (shell:false) - no shell-string interpolation, ever. window hide
// by default (background work is invisible); foreground only when the caller asks for 'show'.
const RUN_TIMEOUT_CAP_MS=120000, RUN_OUTPUT_CAP=64*1024;

function sysInfo(){
 return {ok:true,result:{hostname:os.hostname(),platform:os.platform(),release:os.release(),arch:os.arch(),
  uptimeSec:Math.floor(os.uptime()),totalMem:os.totalmem(),freeMem:os.freemem(),cpus:os.cpus().length,
  user:(os.userInfo()||{}).username}};
}

function runCommand(data,ctx){
 const exe=String(data.exe||'');
 if(!exe||exe.length>500)return {ok:false,error:'bad_exe'};
 const args=Array.isArray(data.args)?data.args.slice(0,50).map(String):[];
 const wait=data.wait===undefined?true:!!data.wait;
 const windowMode=data.window==='show'?'show':'hide';
 let timeoutMs=+(data.timeoutMs||30000);
 if(!Number.isFinite(timeoutMs)||timeoutMs<1000)timeoutMs=30000;
 timeoutMs=Math.min(timeoutMs,RUN_TIMEOUT_CAP_MS);
 let cwd=ctx.scratch;
 if(data.cwd!=null){
  const rp=underRoots(String(data.cwd),ctx.roots,ctx.deny);
  if(!rp)return {ok:false,error:'outside_roots'};
  cwd=rp;
 }
 return new Promise(res=>{
  let child;
  try{child=spawn(exe,args,{cwd,windowsHide:windowMode==='hide',shell:false,detached:!wait,
    stdio:wait?['ignore','pipe','pipe']:['ignore','ignore','ignore']})}
  catch(e){return res({ok:false,error:'spawn_failed'})}
  if(!wait){
   child.unref();
   return res({ok:true,result:{started:true,pid:child.pid,window:windowMode}});
  }
  let out='',err='',done=false,killed=false;
  const cap=s=>s.length>RUN_OUTPUT_CAP?s.slice(0,RUN_OUTPUT_CAP):s;
  child.stdout.on('data',d=>{out=cap(out+d)});
  child.stderr.on('data',d=>{err=cap(err+d)});
  const t0=Date.now();
  const to=setTimeout(()=>{killed=true;try{child.kill()}catch{}},timeoutMs);
  if(to.unref)to.unref();
  child.on('error',()=>{if(done)return;done=true;clearTimeout(to);res({ok:false,error:'spawn_failed'})});
  child.on('close',code=>{if(done)return;done=true;clearTimeout(to);
   res({ok:!killed,error:killed?'timeout':undefined,
    result:{exitCode:code,stdout:out,stderr:err,durationMs:Date.now()-t0,window:windowMode,timedOut:killed}});
  });
 });
}

// open a file (under roots, never denied) or an https URL with its associated app - detached, fire-and-forget
function openPath(data,ctx){
 const p=String(data.path||'');
 if(!p||p.length>1000)return {ok:false,error:'bad_path'};
 let target;
 if(/^https:\/\//i.test(p)){target=p}
 else{target=underRoots(p,ctx.roots,ctx.deny);if(!target)return {ok:false,error:'outside_roots'}}
 try{
  const c=process.platform==='win32'
   ?spawn('cmd.exe',['/c','start','','""',target],{detached:true,stdio:'ignore',windowsHide:true})
   :spawn('xdg-open',[target],{detached:true,stdio:'ignore'});
  c.unref();
  return {ok:true,result:{opened:target}};
 }catch(e){return {ok:false,error:'spawn_failed'}}
}

// closed kind allowlist - the op registry. Every kind still passes the signed-envelope gate.
// null-prototype object: prototype names (constructor, toString, ...) are NOT ops.
const OPS=Object.assign(Object.create(null),{find_files:findFiles,read_file:readFile,write_file:writeFile,sys_info:sysInfo,run_command:runCommand,open_path:openPath});
module.exports={OPS,READ_CAP,WRITE_CAP,defaultDenyDirs};
