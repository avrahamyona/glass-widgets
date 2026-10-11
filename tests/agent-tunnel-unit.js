// Tunnel unit tests: fake spawn/fetch, real fs in a temp dir. No Electron, no network, no cloudflared.
const{URL_RE,ensureCloudflared,startTunnel,CLOUDFLARED}=require('../src/lib/tunnel');
const{EventEmitter}=require('events');
const fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};

async function main(){
 // 1) URL_RE: matches real cloudflared output shapes, rejects lookalikes
 assert('2026-10-11 INF +--------------------------------------------------------------------------------------------+\n2026-10-11 INF |  https://words-here-abc123.trycloudflare.com  |'.match(URL_RE)[0]==='https://words-here-abc123.trycloudflare.com','real shape');
 assert(!'https://evil-trycloudflare.com.evil.tld'.match(URL_RE),'lookalike host rejected');
 assert(!'http://a-b.trycloudflare.com'.match(URL_RE),'http rejected (https only)');
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
  const mk=()=>{const c=new EventEmitter();c.stderr=new EventEmitter();c.stdout=new EventEmitter();c.kill=()=>{c.killed=true};spawns.push(c);return c};
  const t=startTunnel({exePath:'/x',port:47631,spawnImpl:mk,onUrl:u=>urls.push(u),log:(s,o)=>logs.push({s,...o}),initialRetryMs:5,maxRetryMs:10});
  assert(spawns.length===1,'spawned immediately');
  spawns[0].stderr.emit('data',Buffer.from('INF +------------------------------------------------------------------+\n'));
  spawns[0].stderr.emit('data',Buffer.from('INF |  https://alpha-beta-gamma.trycloudflare.com  |\n'));
  spawns[0].stderr.emit('data',Buffer.from('INF |  https://alpha-beta-gamma.trycloudflare.com  |\n')); // same URL again
  assert(urls.length===1&&urls[0]==='https://alpha-beta-gamma.trycloudflare.com','URL reported exactly once');
  spawns[0].emit('exit',1);
  await new Promise(r=>setTimeout(r,30));
  assert(spawns.length===2,'respawned after exit');
  spawns[1].stderr.emit('data',Buffer.from('https://delta-eps.trycloudflare.com\n'));
  assert(urls.length===2&&urls[1]==='https://delta-eps.trycloudflare.com','new URL reported after respawn');
  t.stop();
  spawns[1].emit('exit',1);
  const n=spawns.length;
  await new Promise(r=>setTimeout(r,30));
  assert(spawns.length===n,'no respawn after stop');
  assert(logs.some(l=>l.s==='url')&&logs.some(l=>l.s==='exit'),'lifecycle logged')}

 console.log('AGENT-TUNNEL-UNIT: PASS');
}
main().catch(e=>{console.error('FAIL',e);process.exit(1)});
