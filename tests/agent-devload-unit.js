// Device-load verdict ordering (Electron-free, win32 stubbed): on a FRESH install the device
// dir/file does not exist yet, so loadDevice must judge strict-ENOENT 'absent' WITHOUT any ACL
// probe on the device paths (real win32: Get-Acl on a missing path throws, and the pre-fix order
// mislabeled the fresh install 'acl' - exactly the Get-Acl noise seen on the 0.4.63 slice PC).
// The fail-closed ACL check must STILL fire when the key file EXISTS. Mirrors server/index.js.
const assert=require('assert'),fs=require('fs'),path=require('path'),os=require('os'),crypto=require('crypto'),net=require('net');

// electron stub: agent.js imports {screen} at module top
const Module=require('module'),origLoad=Module._load;
Module._load=function(request){if(request==='electron')return {screen:{getPrimaryDisplay:()=>({size:{width:1920,height:1080}}),getAllDisplays:()=>[]}};return origLoad.apply(this,arguments)};

// win32 stub: loadDevice's ACL branch is platform-gated
const realPlatform=Object.getOwnPropertyDescriptor(process,'platform');
Object.defineProperty(process,'platform',{value:'win32'});

// acl-win stub BEFORE agent.js/durable-store require it. Real win32 semantics: Get-Acl on a
// MISSING path throws -> aclOwnerOnly false; on an existing path the verdict is controllable.
const acl=require('../src/lib/acl-win.js');
let aclCalls=[],aclVerdict=true;
acl.aclOwnerOnly=(p)=>{aclCalls.push(p);return fs.existsSync(p)?aclVerdict:false};
acl.aclHarden=()=>true;
acl.currentSid=()=>'S-1-5-21-1000';

process.env.GLASSWIDGETS_AGENT_CMD_KEY='dl-key';
process.env.GLASSWIDGETS_AGENT_CMD_URL='http://127.0.0.1:1/no-sse';
process.env.GLASSWIDGETS_AGENT_ACK_URL='http://127.0.0.1:1/ack';
process.env.GLASSWIDGETS_AGENT_SIGN_PUB=crypto.generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).toString('base64');
process.env.GLASSWIDGETS_TUNNEL_ENABLED='0';

const AGENT=require('../src/lib/agent.js');
const startOn=(profile)=>{const app={getPath:()=>profile,getVersion:()=>'dl-test'};
 return AGENT({app,rd:()=>({}),wr:()=>{},chatKey:'',broadcastCard:()=>{},broadcastSettle:()=>{}})};

const KP=crypto.generateKeyPairSync('ed25519');
const PRIV_B64=KP.privateKey.export({format:'der',type:'pkcs8'}).toString('base64');
const PUB_B64=KP.publicKey.export({format:'der',type:'spki'}).toString('base64');

const freePort=()=>new Promise(res=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>res(p))})});
const devAclCalls=()=>aclCalls.filter(p=>p.split(/[\\/]/).includes('device'));

async function main(){
 const port=await freePort();
 process.env.GLASSWIDGETS_LOCAL_SERVER_PORT=String(port);
 // profiles must live under the (stubbed-win32) user profile root: durable-store enforces it
 const root=fs.mkdtempSync(path.join(os.homedir(),'.gw-dl-'));

 // 1) fresh install: no device dir -> 'absent', and ZERO ACL probes on device paths (the bug)
 const p1=path.join(root,'p1');
 const A=startOn(p1);
 assert.strictEqual(A.__debug().dev,'absent','fresh install must be absent, got: '+A.__debug().dev);
 assert.strictEqual(devAclCalls().length,0,'no ACL probe on device paths that do not exist yet: '+JSON.stringify(devAclCalls()));
 await A.stop();

 // 2) existing key + ACL failing -> 'acl' (fail-closed preserved)
 const p2=path.join(root,'p2');
 fs.mkdirSync(path.join(p2,'device'),{recursive:true});
 fs.writeFileSync(path.join(p2,'device','device.json'),JSON.stringify({pub:PUB_B64,priv:PRIV_B64}));
 aclVerdict=false;aclCalls=[];
 const B=startOn(p2);
 assert.strictEqual(B.__debug().dev,'acl','existing key with bad ACL must stay fail-closed, got: '+B.__debug().dev);
 assert(devAclCalls().length>=1,'ACL must be probed when the key file exists');
 await B.stop();

 // 3) existing valid key + ACL ok -> 'ok' (same profile, after stop)
 aclVerdict=true;
 const C=startOn(p2);
 assert.strictEqual(C.__debug().dev,'ok','valid key + owner-only ACL -> ok, got: '+C.__debug().dev);
 await C.stop();

 // 4) corrupt file + ACL ok -> 'corrupt'
 fs.writeFileSync(path.join(p2,'device','device.json'),'{"pub":1}corrupt');
 const D=startOn(p2);
 assert.strictEqual(D.__debug().dev,'corrupt','corrupt file -> corrupt, got: '+D.__debug().dev);
 await D.stop();

 // 5) ENROLL-TIME re-judgment (the absent-vs-invalid gate): the boot verdict may be stale.
 // A fresh install boots 'absent'; a broken key appearing AFTER boot must flip the enroll gate
 // to refuse (probe != absent), and removing it must restore 'absent' (mint allowed).
 const p5=path.join(root,'p5');
 aclVerdict=true;
 const E=startOn(p5);
 assert.strictEqual(E.__debug().dev,'absent','p5 boots absent');
 fs.mkdirSync(path.join(p5,'device'),{recursive:true});
 fs.writeFileSync(path.join(p5,'device','device.json'),'{"pub":1}corrupt'); // broken key lands AFTER boot
 assert.strictEqual(E.__enrollHealthProbe(),'corrupt','enroll-time probe re-judges: post-boot corrupt key refuses the mint (gate closed)');
 assert.strictEqual(E.__debug().dev,'corrupt','probe refreshes the shared verdict');
 fs.unlinkSync(path.join(p5,'device','device.json'));
 assert.strictEqual(E.__enrollHealthProbe(),'absent','removing the file restores absent (mint allowed again)');
 fs.writeFileSync(path.join(p5,'device','device.json'),JSON.stringify({pub:PUB_B64,priv:PRIV_B64})); // a HEALTHY key lands after boot
 assert.strictEqual(E.__enrollHealthProbe(),'ok','a healthy post-boot key loads - enroll returns it instead of minting');
 await E.stop();

 // 6) mismatch (stored pub does NOT derive from priv) -> gate closed
 const KP2=crypto.generateKeyPairSync('ed25519');
 fs.writeFileSync(path.join(p5,'device','device.json'),JSON.stringify({pub:KP2.publicKey.export({format:'der',type:'spki'}).toString('base64'),priv:PRIV_B64}));
 const F=startOn(p5);
 assert.strictEqual(F.__enrollHealthProbe(),'mismatch','mismatched stored pub -> mismatch (gate closed)');
 await F.stop();

 fs.rmSync(root,{recursive:true,force:true});
 console.log('DEVLOAD verdict ordering: PASS (fresh=absent without ACL probe, acl fail-closed on existing key, ok, corrupt)');
}
main().then(()=>{Object.defineProperty(process,'platform',realPlatform);process.exit(0)}).catch(e=>{Object.defineProperty(process,'platform',realPlatform);console.error('DEVLOAD FAIL:',e&&e.stack||e);process.exit(1)});
