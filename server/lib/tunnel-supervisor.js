// Tunnel supervisor (Efi-pattern composition for the standalone server): cloudflared quick
// tunnel + respawn supervisor (src/lib/tunnel.js, Electron-free by design) + a LOCAL
// state-file pointer at <dataDir>/tunnel-state.json. No worker, no D1: the rotating
// trycloudflare URL is recorded locally and pushed through pluggable hooks (onPointer).
//
// Efi's method, 1:1: local server -> OUTBOUND quick tunnel (no router/firewall changes -
// the server keeps binding 127.0.0.1) -> supervisor restarts failed tunnels with backoff ->
// every new temporary address lands in a state file. The trade-off is honest: the edge is
// still Cloudflare, but as a dumb free pipe - no account, no quota-bearing service.
//
// Pointer safety model (unchanged from docs/sender-tunnel-contract.md): the pointer itself
// is PUBLIC and untrusted - the sender proves the endpoint with /health?nonce= against the
// enrolled device key before any payload. A stale/wrong pointer fails closed, never talks
// to an impostor. Parity with the app leg: never publish without a device identity.
const fs=require('fs'),path=require('path');
const{ensureCloudflared,startTunnel}=require('../../src/lib/tunnel');

const STATE_FILE='tunnel-state.json';

// Atomic same-dir tmp+rename: a reader never observes a torn state file. A failed write
// leaves the PREVIOUS state intact (the sender's stale window covers the gap).
function writeStateAtomic(file,obj){
 const tmp=file+'.tmp-'+process.pid+'-'+Date.now();
 fs.writeFileSync(tmp,JSON.stringify(obj)+'\n',{mode:0o600});
 fs.renameSync(tmp,file);
}

// Fail-closed read for the sender side: missing -> null; corrupt/non-JSON THROWS (a broken
// state file is evidence of tampering/damage, never a silent "no tunnel").
function readTunnelState(dataDir){
 try{return JSON.parse(fs.readFileSync(path.join(dataDir,STATE_FILE),'utf8'))}catch(e){if(e&&e.code==='ENOENT')return null;throw e}
}

// Starts the supervisor. Returns {started:false,reason} when the tunnel cannot come up
// (unsupported platform, binary unavailable) - the local server keeps running regardless.
// Rec record: {url,deviceId,since,down}. down:true with url:'' means "no live tunnel - the
// last pointer is dead" (the app's best-effort clear + the contract's 90s stale window).
async function startTunnelSupervisor({dataDir,port,log,getDevice,onPointer,fetchImpl,spawnImpl,platform,initialRetryMs,maxRetryMs,isStopped}){
 const say=(stage,obj)=>{try{if(log)log(stage,obj)}catch{}};
 const file=path.join(dataDir,STATE_FILE);
 const publish=(url)=>{
  const d=getDevice&&getDevice();
  if(!d||!d.deviceId){say('no_device_key',{});return} // never publish without device identity (app-leg parity)
  const rec={url:url||'',deviceId:String(d.deviceId),since:new Date().toISOString(),down:!url};
  try{writeStateAtomic(file,rec);say('state',{url:url?'set':'cleared'})}
  catch(e){say('state_write_fail',{err:String(e&&e.message||e).slice(0,120)})}
  if(onPointer)Promise.resolve().then(()=>onPointer(rec)).catch(e=>say('hook_fail',{err:String(e&&e.message||e).slice(0,120)}));
 };
 const exe=await ensureCloudflared(path.join(dataDir,'bin'),{fetchImpl,log:(s,o)=>say(s,o),platform});
 if(!exe){say('not_started',{reason:'no_binary'});return{started:false,reason:'no_binary',file}}
 const t=startTunnel({exePath:exe,port,log:(s,o)=>say(s,o),spawnImpl,initialRetryMs,maxRetryMs,isStopped,
  onUrl:u=>publish(u),
  onDown:()=>publish('')});
 return{started:true,file,stop:()=>t.stop()};
}

module.exports={startTunnelSupervisor,readTunnelState,STATE_FILE,writeStateAtomic};
