// Tunnel-supervisor unit tests: fake spawn/fetch, real fs in temp dirs. No network, no cloudflared.
// Covers the Efi-pattern contract: URL -> state file, rotation -> state updated, down/stop ->
// state cleared, no device identity -> never published, unsupported platform -> never spawns,
// fail-closed state reads, no torn writes left behind.
const{startTunnelSupervisor,readTunnelState,STATE_FILE}=require('../server/lib/tunnel-supervisor');
const{EventEmitter}=require('events');
const fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const mkDir=()=>fs.mkdtempSync(path.join(os.tmpdir(),'gw-tunsup-'));
const seedBin=dir=>{const b=Buffer.from('fake-binary');fs.mkdirSync(path.join(dir,'bin'),{recursive:true});fs.writeFileSync(path.join(dir,'bin','cloudflared'),b);return crypto.createHash('sha256').update(b).digest('hex')}; // off-win32 the file is named 'cloudflared'; ensureCloudflared resolves by process.platform for the name but honors platform:'win32' only for download gating - seed BOTH names to stay platform-neutral
const seedBoth=dir=>{const b=Buffer.from('fake-binary');const h=crypto.createHash('sha256').update(b).digest('hex');fs.mkdirSync(path.join(dir,'bin'),{recursive:true});for(const n of['cloudflared','cloudflared.exe'])fs.writeFileSync(path.join(dir,'bin',n),b);return h};
const mkSpawn=spawns=>(...a)=>{const c=new EventEmitter();c.stderr=new EventEmitter();c.stdout=new EventEmitter();c.kill=()=>{c.killed=true};c.args=a;spawns.push(c);return c};
const emitUrl=(c,u)=>c.stderr.emit('data',Buffer.from('INF Serving at '+u+'\n'));
const noTmpLeft=dir=>fs.readdirSync(path.join(dir)).filter(f=>f.includes('.tmp-')).length===0;

async function main(){
 // 1) happy path: URL line -> state file carries url+deviceId, hook fired
 {const dir=mkDir();const sha=seedBoth(dir);const spawns=[];const hooks=[];
  const r=await startTunnelSupervisor({dataDir:dir,port:47631,platform:'win32',spawnImpl:mkSpawn(spawns),initialRetryMs:5,maxRetryMs:10,
   getDevice:()=>({deviceId:'a1b2c3d4e5f60718'}),onPointer:rec=>hooks.push(rec)});
  assert(r.started===true,'supervisor started with seeded binary');
  assert(spawns.length===1,'tunnel spawned');
  emitUrl(spawns[0],'https://words-here-abc123.trycloudflare.com');
  await sleep(20);
  const st=readTunnelState(dir);
  assert(st&&st.url==='https://words-here-abc123.trycloudflare.com'&&st.deviceId==='a1b2c3d4e5f60718'&&st.down===false&&typeof st.since==='string','state file carries url+device+ts');
  assert(hooks.length===1&&hooks[0].url===st.url,'hook fired once with the record');
  assert(noTmpLeft(dir),'no torn tmp left after write');
  r.stop();await sleep(20)}

 // 2) rotation: exit -> respawn -> new URL -> state updated; stop -> down:true cleared pointer
 {const dir=mkDir();const sha=seedBoth(dir);const spawns=[];const hooks=[];
  const r=await startTunnelSupervisor({dataDir:dir,port:47631,platform:'win32',spawnImpl:mkSpawn(spawns),initialRetryMs:5,maxRetryMs:10,
   getDevice:()=>({deviceId:'a1b2c3d4e5f60718'}),onPointer:rec=>hooks.push(rec)});
  emitUrl(spawns[0],'https://alpha-one-111.trycloudflare.com');await sleep(20);
  spawns[0].emit('exit',6);await sleep(40); // backoff 5-10ms, then respawn
  assert(spawns.length===2,'supervisor respawned after tunnel death');
  emitUrl(spawns[1],'https://beta-two-222.trycloudflare.com');await sleep(20);
  let st=readTunnelState(dir);
  assert(st.url==='https://beta-two-222.trycloudflare.com'&&st.down===false,'rotated address replaced in state file');
  r.stop();await sleep(20);
  st=readTunnelState(dir);
  assert(st.url===''&&st.down===true,'stop clears the pointer with down:true NOW');
  assert(noTmpLeft(dir),'no torn tmp after rotation')}

 // 3) down mid-episode (process error, not stop): state cleared, later respawn re-publishes
 {const dir=mkDir();seedBoth(dir);const spawns=[];
  const r=await startTunnelSupervisor({dataDir:dir,port:47631,platform:'win32',spawnImpl:mkSpawn(spawns),initialRetryMs:5,maxRetryMs:10,getDevice:()=>({deviceId:'a1b2c3d4e5f60718'})});
  emitUrl(spawns[0],'https://alpha-one-111.trycloudflare.com');await sleep(20);
  spawns[0].emit('exit',1);await sleep(20);
  let st=readTunnelState(dir);
  assert(st.url===''&&st.down===true,'tunnel death clears the state pointer');
  await sleep(30);assert(spawns.length===2,'respawn scheduled after death');
  emitUrl(spawns[1],'https://gamma-three-333.trycloudflare.com');await sleep(20);
  st=readTunnelState(dir);
  assert(st.url==='https://gamma-three-333.trycloudflare.com'&&st.down===false,'new episode republishes');
  r.stop();await sleep(20)}

 // 4) no device identity -> URL arrives but NOTHING is published (app-leg parity)
 {const dir=mkDir();seedBoth(dir);const spawns=[];const hooks=[];
  const r=await startTunnelSupervisor({dataDir:dir,port:47631,platform:'win32',spawnImpl:mkSpawn(spawns),initialRetryMs:5,maxRetryMs:10,
   getDevice:()=>null,onPointer:rec=>hooks.push(rec)});
  emitUrl(spawns[0],'https://words-here-abc123.trycloudflare.com');await sleep(20);
  assert(readTunnelState(dir)===null,'no state file without device identity');
  assert(hooks.length===0,'no hook call without device identity');
  r.stop();await sleep(20)}

 // 5) unsupported platform: no binary, no spawn, local server unaffected
 {const dir=mkDir();const spawns=[];
  const r=await startTunnelSupervisor({dataDir:dir,port:47631,platform:'linux',spawnImpl:mkSpawn(spawns),initialRetryMs:5,maxRetryMs:10,getDevice:()=>({deviceId:'a1b2c3d4e5f60718'})});
  assert(r.started===false&&r.reason==='no_binary','unsupported platform reports no_binary');
  assert(spawns.length===0,'never spawns on unsupported platform')}

 // 6) fail-closed reads: missing -> null, corrupt -> throws
 {const dir=mkDir();
  assert(readTunnelState(dir)===null,'missing state -> null');
  fs.writeFileSync(path.join(dir,STATE_FILE),'{corrupt');
  let threw=false;try{readTunnelState(dir)}catch{threw=true}
  assert(threw,'corrupt state throws, never silently ignored')}

 // 7) hook failure never kills the supervisor or the state write
 {const dir=mkDir();seedBoth(dir);const spawns=[];
  const r=await startTunnelSupervisor({dataDir:dir,port:47631,platform:'win32',spawnImpl:mkSpawn(spawns),initialRetryMs:5,maxRetryMs:10,
   getDevice:()=>({deviceId:'a1b2c3d4e5f60718'}),onPointer:()=>{throw new Error('hook exploded')}});
  emitUrl(spawns[0],'https://words-here-abc123.trycloudflare.com');await sleep(30);
  const st=readTunnelState(dir);
  assert(st&&st.url==='https://words-here-abc123.trycloudflare.com','state written even when hook throws');
  r.stop();await sleep(20)}

 // 8) wiring: real boot with GW_TUNNEL=1 on a non-Windows host - server still up, tunnel reports
 // no_binary, nothing spawned. (On Windows with a verified binary it would supervise for real.)
 {const{spawn}=require('child_process');const dir=mkDir();
  const{publicKey:PUB}=crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(dir,'config.json'),JSON.stringify({token:'srv-key',senderPub:PUB.export({format:'der',type:'spki'}).toString('base64'),port:0,roots:[dir]}));
  const cp=spawn(process.execPath,['server/index.js'],{env:{...process.env,GW_SERVER_CONFIG:path.join(dir,'config.json'),GW_TUNNEL:'1'},stdio:['ignore','pipe','pipe']});
  let out='';cp.stdout.on('data',d=>out+=d);
  for(let i=0;i<60&&!out.includes('tunnel');i++)await sleep(200);
  assert(out.includes('server up'),'server still boots with GW_TUNNEL=1');
  if(process.platform!=='win32')assert(out.includes('tunnel not started: no_binary'),'non-Windows boot reports tunnel off: '+out);
  await new Promise(res=>{cp.once('exit',res);cp.kill('SIGTERM');setTimeout(res,3000).unref()})}

 console.log('TUNNEL-SUPERVISOR-UNIT: PASS');
}
main().catch(e=>{console.error('FAIL',e);process.exit(1)});
