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


// readFileBytes: the streaming /file route's scope-checked fetch (same underRoots+deny as the
// ops, same READ_CAP). Returns {buf,sha256,size,rp} or null - null is indistinguishable refusal.
function readFileBytes(p,ctx){
 const rp=underRoots(String(p||''),ctx.roots,ctx.deny);
 if(!rp)return null;
 let st;try{st=fs.statSync(rp)}catch{return null}
 if(!st.isFile()||st.size>READ_CAP)return null;
 const buf=fs.readFileSync(rp);
 return{buf,sha256:crypto.createHash('sha256').update(buf).digest('hex'),size:st.size,rp};
}

// --- stage 3: screenshot + UI input via inbox Windows components (zero-dep, user-approved) ---
// PowerShell is invoked with -EncodedCommand (UTF-16LE base64) - no script files are written.
// These act on the USER'S LIVE interactive session: clicks/typing are visible by nature.
let psRunImpl=null; // tests inject a stub via __setPsRunForTests; production spawns powershell.exe
function psRun(script,timeoutMs){
 if(psRunImpl)return Promise.resolve(psRunImpl(script,timeoutMs));
 const enc=Buffer.from(script,'utf16le').toString('base64');
 return new Promise(res=>{
  let child;try{child=spawn('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',enc],{windowsHide:true,stdio:['ignore','pipe','pipe']})}
  catch(e){return res({ok:false,error:'spawn_failed'})}
  let out='',err='';
  child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>err+=d);
  const to=setTimeout(()=>{try{child.kill()}catch{}},timeoutMs||45000);if(to.unref)to.unref();
  child.on('error',()=>{clearTimeout(to);res({ok:false,error:'spawn_failed'})});
  child.on('close',code=>{clearTimeout(to);res({ok:code===0,exitCode:code,stdout:String(out).slice(0,60000),stderr:String(err).slice(0,20000)})});
 });
}

const UI_CSHARP=[
 'using System;',
 'using System.Runtime.InteropServices;',
 'public class GWUI {',
 ' [DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y);',
 ' [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);',
 ' [DllImport("user32.dll")] public static extern void mouse_event(uint flags,uint dx,uint dy,uint data,IntPtr extra);',
 ' [DllImport("user32.dll")] public static extern uint SendInput(uint n,INPUT[] inputs,int size);',
 ' public struct POINT{public int X;public int Y;}',
 ' [StructLayout(LayoutKind.Sequential)] public struct INPUT{public uint type;public IO u;}',
 ' [StructLayout(LayoutKind.Explicit)] public struct IO{[FieldOffset(0)]public KEYBDINPUT k;[FieldOffset(0)]public MOUSEINPUT m;}',
 ' [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT{public ushort vk;public ushort scan;public uint flags;public uint time;public IntPtr extra;}',
 ' [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT{public int dx;public int dy;public uint data;public uint flags;public uint time;public IntPtr extra;}',
 ' public static void TypeText(string s){',
 '  foreach(char c in s){',
 '   INPUT[] dn=new INPUT[]{new INPUT{type=1,u=new IO{k=new KEYBDINPUT{vk=0,scan=c,flags=4,time=0,extra=IntPtr.Zero}}}};',
 '   INPUT[] up=new INPUT[]{new INPUT{type=1,u=new IO{k=new KEYBDINPUT{vk=0,scan=c,flags=6,time=0,extra=IntPtr.Zero}}}};',
 '   SendInput(1,dn,Marshal.SizeOf(typeof(INPUT)));',
 '   SendInput(1,up,Marshal.SizeOf(typeof(INPUT)));',
 '  }',
 ' }',
 ' public static void Key(ushort vk,bool down){',
 '  INPUT[] i=new INPUT[]{new INPUT{type=1,u=new IO{k=new KEYBDINPUT{vk=vk,scan=0,flags=(uint)(down?0:2),time=0,extra=IntPtr.Zero}}}};',
 '  SendInput(1,i,Marshal.SizeOf(typeof(INPUT)));',
 ' }',
 '}',
 'Add-Type -TypeDefinition $GWCS -ReferencedAssemblies System.Drawing,System.Windows.Forms'].join('\n');
// the script preamble carries the C# in a PS here-string
const UI_PREAMBLE='$GWCS=@"\n'+UI_CSHARP.split('\n').slice(0,-1).join('\n')+'\n"@\n'+UI_CSHARP.split('\n').slice(-1)[0];

async function screenshot(data,ctx){
 const scale=data.scale==null?1:+data.scale;
 if(!Number.isFinite(scale)||scale<0.1||scale>1)return{ok:false,error:'bad_scale'};
 const quality=Math.min(95,Math.max(20,+(data.quality||70)||70));
 const dir=ctx.workDir||ctx.roots[0];
 try{fs.mkdirSync(dir,{recursive:true})}catch{}
 const tp=writeTarget(path.join(dir,'shot-'+Date.now()+'.jpg'),ctx.roots,ctx.deny);
 if(!tp)return{ok:false,error:'outside_roots'};
 const lines=[
  'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
  '$b=[System.Windows.Forms.SystemInformation]::VirtualScreen',
  '$bmp=New-Object System.Drawing.Bitmap ($b.Width),($b.Height)',
  '$g=[System.Drawing.Graphics]::FromImage($bmp)',
  '$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size)'];
 if(scale!==1)lines.push('$w=[int]($bmp.Width*'+scale+');$h=[int]($bmp.Height*'+scale+')','$nb=New-Object System.Drawing.Bitmap $bmp,$w,$h','$g.Dispose();$bmp.Dispose()','$bmp=$nb','$g=[System.Drawing.Graphics]::FromImage($bmp)');
 lines.push(
  "$enc=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|?{$_.MimeType-eq'image/jpeg'}",
  '$ep=New-Object System.Drawing.Imaging.EncoderParameters(1)',
  '$ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]'+quality+')',
  "$bmp.Save('"+tp.replace(/'/g,"''")+"',$enc,$ep)",
  '$g.Dispose();$bmp.Dispose()',
  "Write-Host ('SHOT '+$b.Width+'x'+$b.Height)");
 const r=await psRun(lines.join('; '),45000);
 if(!r.ok)return{ok:false,error:'ui_failed',detail:String(r.stderr||r.stdout||'').slice(0,300)};
 const m=/SHOT (\d+)x(\d+)/.exec(r.stdout||'');
 let st;try{st=fs.statSync(tp)}catch{return{ok:false,error:'no_capture'}};
 const buf=fs.readFileSync(tp);
 return{ok:true,result:{path:tp,screenWidth:m?+m[1]:0,screenHeight:m?+m[2]:0,bytes:st.size,scale,quality,sha256:crypto.createHash('sha256').update(buf).digest('hex'),note:'fetch the bytes via signed GET /file?path=...'}};
}

const VK={enter:13,return:13,tab:9,esc:27,escape:27,backspace:8,del:46,delete:46,up:38,down:40,left:37,right:39,home:36,end:35,space:32,pgup:33,pgdn:34};
const MODVK={ctrl:17,control:17,shift:16,alt:18,win:91};
async function uiAutomation(data,ctx){
 const action=String(data.action||'');
 const body=[];
 if(action==='click'||action==='move'){
  const x=Math.round(+data.x),y=Math.round(+data.y);
  if(!Number.isFinite(x)||!Number.isFinite(y)||x<0||y<0||x>10000||y>10000)return{ok:false,error:'bad_coords'};
  body.push('[GWUI]::SetCursorPos('+x+','+y+')|Out-Null');
  if(action==='click'){
   const button=String(data.button||'left');
   let seq;
   if(button==='right')seq=['[GWUI]::mouse_event(8,0,0,0,[IntPtr]::Zero)','[GWUI]::mouse_event(16,0,0,0,[IntPtr]::Zero)'];
   else seq=['[GWUI]::mouse_event(2,0,0,0,[IntPtr]::Zero)','[GWUI]::mouse_event(4,0,0,0,[IntPtr]::Zero)'];
   body.push(seq[0],'Start-Sleep -Milliseconds 40',seq[1]);
   if(button==='double')body.push('Start-Sleep -Milliseconds 90',seq[0],'Start-Sleep -Milliseconds 40',seq[1]);
  }
 }else if(action==='type'){
  const text=String(data.text||'');
  if(!text||text.length>2000)return{ok:false,error:'bad_text'};
  body.push("[GWUI]::TypeText('"+text.replace(/'/g,"''")+"')");
 }else if(action==='key'){
  const key=String(data.key||'').toLowerCase();
  const vk=VK[key];if(!vk)return{ok:false,error:'bad_key'};
  const mods=Array.isArray(data.modifiers)?data.modifiers.map(m=>MODVK[String(m).toLowerCase()]).filter(Boolean):[];
  for(const mv of mods)body.push('[GWUI]::Key('+mv+',$true)');
  body.push('[GWUI]::Key('+vk+',$true)','Start-Sleep -Milliseconds 40','[GWUI]::Key('+vk+',$false)');
  for(const mv of mods.slice().reverse())body.push('[GWUI]::Key('+mv+',$false)');
 }else if(action==='position'){
  // just report the cursor position below
 }else return{ok:false,error:'bad_action'};
 body.push('$p=New-Object GWUI+POINT','[GWUI]::GetCursorPos([ref]$p)|Out-Null',"Write-Host ('POS '+$p.X+','+$p.Y)");
 const r=await psRun(UI_PREAMBLE+'\n'+body.join('\n'),45000);
 if(!r.ok)return{ok:false,error:'ui_failed',detail:String(r.stderr||r.stdout||'').slice(0,300)};
 const m=/POS (\d+),(\d+)/.exec(r.stdout||'');
 return{ok:true,result:{action,pos:m?{x:+m[1],y:+m[2]}:null}};
}

// closed kind allowlist - the op registry. Every kind still passes the signed-envelope gate.
// null-prototype object: prototype names (constructor, toString, ...) are NOT ops.
const OPS=Object.assign(Object.create(null),{find_files:findFiles,read_file:readFile,write_file:writeFile,sys_info:sysInfo,run_command:runCommand,open_path:openPath,screenshot:screenshot,ui_automation:uiAutomation});
function __setPsRunForTests(fn){psRunImpl=fn}
module.exports={OPS,READ_CAP,WRITE_CAP,defaultDenyDirs,readFileBytes,__setPsRunForTests};
