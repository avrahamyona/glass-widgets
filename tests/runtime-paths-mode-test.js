// runtime-paths mode (--gw-runtime-paths-json): spawns the REAL app entry under Electron and
// verifies the evidence contract: single JSON line, exact nonce echo, all required fields,
// exit 0, and a fast exit (no boot fallthrough - a booted app would hold the process open).
// Run: TUNNEL_ENABLED=0 xvfb-run -a node tests/runtime-paths-mode-test.js
const assert=require('assert'),{spawn}=require('child_process'),path=require('path');
const electron=require('electron'),root=path.join(__dirname,'..');
function run(args){return new Promise((res,rej)=>{
 const t0=Date.now();
 const c=spawn(electron,[root,...args],{stdio:['ignore','pipe','pipe']});
 let out='',err='';c.stdout.on('data',d=>out+=d);c.stderr.on('data',d=>err+=d);
 const kill=setTimeout(()=>{c.kill('SIGKILL');rej(new Error('mode did not exit within 30s - boot fallthrough suspected'))},30000);
 c.on('close',code=>{clearTimeout(kill);res({code,out,err,ms:Date.now()-t0})});c.on('error',rej)})}
(async()=>{
 const nonce='unit-nonce-'+Date.now();
 const r=await run(['--gw-runtime-paths-json',nonce]);
 assert.strictEqual(r.code,0,'exit 0, got '+r.code+' stderr: '+r.err.slice(0,200));
 const lines=r.out.trim().split('\n').filter(l=>l.trim().startsWith('{'));
 assert.strictEqual(lines.length,1,'exactly one JSON line, got: '+r.out.slice(0,200));
 const j=JSON.parse(lines[0]);
 assert.strictEqual(j.nonce,nonce,'nonce echoed exactly');
 assert.strictEqual(j.v,1,'schema v1');
 for(const k of ['ts','name','version','isPackaged','exe','appPath','appData','userData'])assert(j[k]!==undefined&&j[k]!=='' ,'field '+k+' present');
 assert.strictEqual(typeof j.isPackaged,'boolean','isPackaged boolean');
 assert(j.userData.startsWith(j.appData),'userData under appData');
 const bad=await run(['--gw-runtime-paths-json','xx']);
 assert.strictEqual(bad.code,2,'bad nonce exits 2');
 assert(!bad.out.trim().startsWith('{'),'bad nonce prints no JSON');
 console.log('RUNTIME-PATHS-MODE-TEST: PASS');
})().catch(e=>{console.error('FAIL',e);process.exit(1)});
