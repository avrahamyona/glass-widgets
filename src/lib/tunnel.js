// Quick-tunnel manager (own-server path B): runs cloudflared against the embedded localhost server,
// extracts the rotating trycloudflare URL, and lets the agent publish it to the worker discovery
// record. The binary is pinned by version AND sha256 - a bad download never runs.
// Electron-free by design so tests/agent-tunnel-unit.js can drive it with fake spawn/fetch.
const fs=require('fs'),path=require('path'),crypto=require('crypto');

const CLOUDFLARED={
 version:'2026.10.0',
 url:'https://github.com/cloudflare/cloudflared/releases/download/2026.10.0/cloudflared-windows-amd64.exe',
 sha256:'86aee4017b26625cee8484c113558f48effa4cd47f7aa05fcf425604e5d2b23c' // cloudflared-windows-amd64.exe, computed from the official release asset
};
const URL_RE=/https:\/\/[^\s"'|<>]+/i; // candidate token only - validateTunnelUrl decides
// exact-host validation: a candidate is a tunnel URL ONLY if it parses as https with no
// credentials and its hostname is exactly one label under trycloudflare.com - so
// https://a.trycloudflare.com.evil.example and https://a.trycloudflare.com@evil.example both fail.
function validateTunnelUrl(u){
 try{const x=new URL(u);
  return x.protocol==='https:'&&!x.username&&!x.password&&(x.port===''||x.port==='443')&&/^[a-z0-9-]{1,63}\.trycloudflare\.com$/.test(x.hostname)?u:null
 }catch{return null}
}

function sha256File(p){return new Promise((res,rej)=>{const h=crypto.createHash('sha256');const s=fs.createReadStream(p);s.on('data',d=>h.update(d));s.on('end',()=>res(h.digest('hex')));s.on('error',rej)})}

// Ensures binDir/cloudflared(.exe) exists with the pinned hash; downloads+verifies when missing.
// Returns the binary path, or null (tunnel stays off, SSE fallback keeps running).
async function ensureCloudflared(binDir,{sha256,url,fetchImpl,log,platform}={}){
 const say=(stage,obj)=>{try{if(log)log(stage,obj)}catch{}};
 const plat=platform||process.platform;
 if(plat!=='win32'){say('unsupported_platform',{platform:plat});return null} // the pinned asset is the Windows exe; never download a binary this host cannot run
 const want=(sha256||CLOUDFLARED.sha256).toLowerCase();
 const exe=path.join(binDir,process.platform==='win32'?'cloudflared.exe':'cloudflared');
 try{if((await sha256File(exe))===want){say('present',{exe});return exe}}catch{}
 const dl=url||CLOUDFLARED.url;
 try{
  const f=fetchImpl||fetch;
  const r=await f(dl,{signal:AbortSignal.timeout(120000)});
  if(!r.ok){say('download_fail',{status:r.status});return null}
  const buf=Buffer.from(await r.arrayBuffer());
  fs.mkdirSync(binDir,{recursive:true});
  const tmp=exe+'.download';
  fs.writeFileSync(tmp,buf);
  const got=await sha256File(tmp);
  if(got!==want){fs.unlinkSync(tmp);say('hash_mismatch',{got:got.slice(0,16),want:want.slice(0,16)});return null}
  fs.renameSync(tmp,exe);
  say('downloaded',{bytes:buf.length});
  return exe;
 }catch(e){say('download_error',{err:String(e&&e.message||e).slice(0,120)});return null}
}

// Spawns `cloudflared tunnel --url http://127.0.0.1:<port>`, watches output for the trycloudflare
// URL, reports it once per process via onUrl, and respawns with backoff after exit until stop().
function startTunnel({exePath,port,onUrl,onDown,log,spawnImpl,initialRetryMs,maxRetryMs,isStopped}){
 const{spawn}=spawnImpl?{spawn:spawnImpl}:require('child_process');
 const say=(stage,obj)=>{try{if(log)log(stage,obj)}catch{}};
 const down=()=>{try{if(onDown)onDown()}catch{}};
 let stopped=false,child=null,retry=initialRetryMs||2000;
 const MAX=maxRetryMs||30000;
 const isDead=()=>stopped||(isStopped&&isStopped());
 function launch(){
  if(isDead())return;
  let reported=false,buf='',dead=false; // dead: schedule recovery exactly once, whether 'error', 'exit', or both fire
  try{child=spawn(exePath,['tunnel','--url','http://127.0.0.1:'+port,'--no-autoupdate'],{windowsHide:true})}catch(e){say('spawn_fail',{err:String(e&&e.message||e).slice(0,120)});down();return schedule()}
  const onData=d=>{if(dead||isDead())return;buf+=d.toString(); // late output after error/stop must never fire onUrl
   let i;while((i=buf.indexOf('\n'))>=0){const line=buf.slice(0,i);buf=buf.slice(i+1);
   if(!reported){const m=line.match(URL_RE);const ok=m&&validateTunnelUrl(m[0]);if(ok){reported=true;retry=initialRetryMs||2000;say('url',{url:ok});try{onUrl(ok)}catch{}}}}};
  if(child.stderr)child.stderr.on('data',onData);
  if(child.stdout)child.stdout.on('data',onData);
  const terminal=(stage,obj)=>{if(dead)return;dead=true;say(stage,obj);child=null;down();schedule()};
  child.on('error',e=>terminal('spawn_error',{err:String(e&&e.message||e).slice(0,120)}));
  child.on('exit',(code)=>terminal('exit',{code}));
 }
 function schedule(){if(isDead())return;const wait=retry;retry=Math.min(retry*2,MAX);setTimeout(()=>{if(!isDead())launch()},wait).unref?.()}
 launch();
 return {stop:()=>{stopped=true;try{if(child)child.kill()}catch{}}};
}

module.exports={CLOUDFLARED,URL_RE,validateTunnelUrl,ensureCloudflared,startTunnel};
