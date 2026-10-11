// Tunnel unit tests: fake spawn/fetch, real fs in a temp dir. No Electron, no network, no cloudflared.
const{URL_RE,ensureCloudflared,startTunnel,CLOUDFLARED}=require('../src/lib/tunnel');
const{EventEmitter}=require('events');
const fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};

async function main(){
 // 1) validateTunnelUrl: exact-host validation (ops's verified lookalikes must fail)
 const{validateTunnelUrl}=require('../src/lib/tunnel');
 assert(validateTunnelUrl('https://words-here-abc123.trycloudflare.com')==='https://words-here-abc123.trycloudflare.com','real tunnel URL accepted');
 assert(validateTunnelUrl('https://a-b.trycloudflare.com.evil.example')===null,'suffix host rejected');
 assert(validateTunnelUrl('https://a-b.trycloudflare.com@evil.example')===null,'userinfo hijack rejected');
 assert(validateTunnelUrl('https://evil-trycloudflare.com')===null,'near-miss host rejected');
 assert(validateTunnelUrl('http://a-b.trycloudflare.com')===null,'http rejected');
 assert(validateTunnelUrl('https://a-b.trycloudflare.com:8443')===null,'odd port rejected');
 assert(CLOUDFLARED.version&&/^[0-9a-f]{64}$/.test(CLOUDFLARED.sha256),'pinned version+hash present');

 // 2) ensureCloudflared: matching file is kept, no download
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gw-tunnel-'));
 const exe=path.join(dir,'cloudflared');
 const good=Buffer.from('fake-binary');
 const goodHash=crypto.createHash('sha256').update(good).digest('hex');
 fs.writeFileSync(exe,good);
 {let dl=0;const p=await ensureCloudflared(dir,{sha256:goodHash,fetchImpl:async()=>{dl++;throw new Error('must not download')}});
  assert(p===exe&&dl===0,'matching binary reused, no download')}

 // 3) wrong hash -> downloads, verifies, installs
 fs.writeFileSync(exe,Buffer.from('stale'));
 {const p=await ensureCloudflared(dir,{sha256:goodHash,url:'https://example.test/cf',fetchImpl:async(u)=>{assert(u==='https://example.test/cf','pinned url used');return{ok:true,arrayBuffer:async()=>good.buffer.slice(good.byteOffset,good.byteOffset+good.length)}}});
  assert(p===exe&&(await crypto.subtle.digest('SHA-256',fs.readFileSync(exe)).then(b=>Buffer.from(b).toString('hex')))===goodHash,'downloaded binary installed after hash check')}

 // 4) hash mismatch on download -> rejected, nothing installed
 fs.rmSync(exe);
 {const p=await ensureCloudflared(dir,{sha256:'0'.repeat(64),fetchImpl:async()=>({ok:true,arrayBuffer:async()=>good.buffer.slice(good.byteOffset,good.byteOffset+good.length)})});
  assert(p===null&&!fs.existsSync(exe),'mismatched download never lands')}

 // 5) http failure -> null, no throw
 {const p=await ensureCloudflared(dir,{sha256:goodHash,fetchImpl:async()=>({ok:false,status:503})});
  assert(p===null,'503 -> null')}

 // 6) startTunnel: URL reported once per process, respawn after exit, stop kills
 {const spawns=[];let urls=[];const logs=[];
  const mk=(...a)=>{const c=new EventEmitter();c.stderr=new EventEmitter();c.stdout=new EventEmitter();c.kill=()=>{c.killed=true};c.args=a;spawns.push(c);return c};
  const downs=[];const t=startTunnel({exePath:'/x',port:47631,spawnImpl:mk,onUrl:u=>urls.push(u),onDown:()=>downs.push(1),log:(s,o)=>logs.push({s,...o}),initialRetryMs:5,maxRetryMs:10});
  assert(spawns.length===1,'spawned immediately');
  assert(spawns[0].args[2]&&spawns[0].args[2].windowsHide===true,'spawn uses windowsHide (no console window on Windows)');
  spawns[0].stderr.emit('data',Buffer.from('INF +------------------------------------------------------------------+\n'));
  spawns[0].stderr.emit('data',Buffer.from('INF |  https://alpha-beta-gamma.trycloudflare.com.evil.example  |\n')); // ops lookalike 1: ignored
  spawns[0].stderr.emit('data',Buffer.from('INF |  https://alpha-beta-gamma.trycloudflare.com@evil.example  |\n')); // ops lookalike 2: ignored
  assert(urls.length===0,'lookalike URLs never reported');
  spawns[0].stderr.emit('data',Buffer.from('INF |  https://alpha-beta-gamma.trycloudflare.com  |\n'));
  spawns[0].stderr.emit('data',Buffer.from('INF |  https://alpha-beta-gamma.trycloudflare.com  |\n')); // same URL again
  assert(urls.length===1&&urls[0]==='https://alpha-beta-gamma.trycloudflare.com','URL reported exactly once');
  spawns[0].emit('exit',1);
  await new Promise(r=>setTimeout(r,30));
  assert(spawns.length===2,'respawned after exit');
  spawns[1].stderr.emit('data',Buffer.from('https://delta-eps.trycloudflare.com\n'));
  assert(urls.length===2&&urls[1]==='https://delta-eps.trycloudflare.com','new URL reported after respawn');
  assert(downs.length===1,'onDown fired once on exit (heartbeat must stop with the process)');
  t.stop();
  spawns[1].emit('exit',1);
  const n=spawns.length;
  await new Promise(r=>setTimeout(r,30));
  assert(spawns.length===n,'no respawn after stop');
  assert(logs.some(l=>l.s==='url')&&logs.some(l=>l.s==='exit'),'lifecycle logged')}

 // 7) error-without-exit recovers; error+exit schedules exactly once
 {const spawns2=[];const mk2=()=>{const c=new EventEmitter();c.stderr=new EventEmitter();c.stdout=new EventEmitter();c.kill=()=>{};spawns2.push(c);return c};
  const t=startTunnel({exePath:'/x',port:1,spawnImpl:mk2,onUrl:()=>{},log:()=>{},initialRetryMs:5,maxRetryMs:10});
  spawns2[0].emit('error',new Error('ENOENT')); // error, NO exit event
  await new Promise(r=>setTimeout(r,30));
  assert(spawns2.length===2,'error-without-exit schedules recovery');
  spawns2[1].emit('error',new Error('x'));spawns2[1].emit('exit',1); // both fire on one process
  await new Promise(r=>setTimeout(r,30));
  assert(spawns2.length===3,'error+exit schedules exactly one recovery');
  t.stop()}

 // 8) isStopped gate: a flipped flag between exit and retry prevents the relaunch
 {const spawns3=[];const mk3=()=>{const c=new EventEmitter();c.stderr=new EventEmitter();c.stdout=new EventEmitter();c.kill=()=>{};spawns3.push(c);return c};
  let dead=false;
  const t=startTunnel({exePath:'/x',port:1,spawnImpl:mk3,onUrl:()=>{},log:()=>{},initialRetryMs:5,maxRetryMs:10,isStopped:()=>dead});
  spawns3[0].emit('exit',1);
  dead=true;
  await new Promise(r=>setTimeout(r,30));
  assert(spawns3.length===1,'isStopped blocks the relaunch after exit');
  t.stop()}

 console.log('AGENT-TUNNEL-UNIT: PASS');
}
main().catch(e=>{console.error('FAIL',e);process.exit(1)});
