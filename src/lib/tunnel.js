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
const URL_RE=/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i;

function sha256File(p){return new Promise((res,rej)=>{const h=crypto.createHash('sha256');const s=fs.createReadStream(p);s.on('data',d=>h.update(d));s.on('end',()=>res(h.digest('hex')));s.on('error',rej)})}

// Ensures binDir/cloudflared(.exe) exists with the pinned hash; downloads+verifies when missing.
// Returns the binary path, or null (tunnel stays off, SSE fallback keeps running).
async function ensureCloudflared(binDir,{sha256,url,fetchImpl,log}={}){
 const say=(stage,obj)=>{try{if(log)log(stage,obj)}catch{}};
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
function startTunnel({exePath,port,onUrl,log,spawnImpl,initialRetryMs,maxRetryMs}){
 const{spawn}=spawnImpl?{spawn:spawnImpl}:require('child_process');
 const say=(stage,obj)=>{try{if(log)log(stage,obj)}catch{}};
 let stopped=false,child=null,retry=initialRetryMs||2000;
 const MAX=maxRetryMs||30000;
 function launch(){
  if(stopped)return;
  let reported=false,buf='';
  try{child=spawn(exePath,['tunnel','--url','http://127.0.0.1:'+port,'--no-autoupdate'])}catch(e){say('spawn_fail',{err:String(e&&e.message||e).slice(0,120)});return schedule()}
  const onData=d=>{buf+=d.toString();let i;while((i=buf.indexOf('\n'))>=0){const line=buf.slice(0,i);buf=buf.slice(i+1);
   if(!reported){const m=line.match(URL_RE);if(m){reported=true;retry=initialRetryMs||2000;say('url',{url:m[0]});try{onUrl(m[0])}catch{}}}}};
  if(child.stderr)child.stderr.on('data',onData);
  if(child.stdout)child.stdout.on('data',onData);
  child.on('error',e=>{say('spawn_error',{err:String(e&&e.message||e).slice(0,120)})});
  child.on('exit',(code)=>{say('exit',{code});child=null;schedule()});
 }
 function schedule(){if(stopped)return;const wait=retry;retry=Math.min(retry*2,MAX);setTimeout(()=>{if(!stopped)launch()},wait).unref?.()}
 launch();
 return {stop:()=>{stopped=true;try{if(child)child.kill()}catch{}}};
}

module.exports={CLOUDFLARED,URL_RE,ensureCloudflared,startTunnel};
