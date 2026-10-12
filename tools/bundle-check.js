// Worker bundle validation (review round 4/5 readiness item): proves the worker code bundles as
// platform-neutral ESM with ZERO node builtins (the live Worker runs ESM with NO node-compat flag)
// and that the bundled signer still signs + refuses exactly like the source. Run: node tools/bundle-check.js
// Requires: npx esbuild (fetched on demand), node >= 16 for the smoke run.
const{execSync}=require('child_process'),fs=require('fs'),os=require('os'),path=require('path');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'gw-bundle-'));
const run=c=>execSync(c,{stdio:'pipe'}).toString();
try{
 let i=0;
 for(const f of ['worker/outbound-sign.js','worker/tunnel-route.js']){
  const out=path.join(tmp,'out'+(i++)+'.js'); // one output per entry - never overwrite
  fs.writeFileSync(path.join(tmp,'entry.js'),`export * as m from '${path.resolve(f)}';\n`);
  run(`npx -y esbuild@0.28.2 ${path.join(tmp,'entry.js')} --bundle --format=esm --platform=neutral --outfile=${out}`);
  const b=fs.readFileSync(out,'utf8');
  for(const bad of ['require("fs','require(\'fs','require("path','Buffer.byteLength','process.env.'])
   if(b.includes(bad))throw new Error(f+': node builtin leaked into the neutral bundle: '+bad);
 }
 const smoke=`import {m as signer} from '${path.join(tmp,'out0.js')}'; // out0 = outbound-sign
  import crypto from 'crypto';
  const {privateKey}=crypto.generateKeyPairSync('ed25519');
  const env={GW_SIGN_PRIVATE:privateKey.export({format:'der',type:'pkcs8'}).toString('base64')};
  const e=await signer.buildCommandEnvelope(env,{id:'cmd-0001',kind:'find_files',device:'0123456789abcdef',data:{q:'x'}});
  let threw=false;try{await signer.buildCommandEnvelope(env,{id:'cmd-0001',kind:'find_files',device:'0123456789abcdef',data:{__tunnel:true}})}catch{threw=true}
  if(e.sig.length!==128||!threw)process.exit(1);`;
 fs.writeFileSync(path.join(tmp,'smoke.mjs'),smoke);
 run(`node ${path.join(tmp,'smoke.mjs')}`);
 console.log('BUNDLE-CHECK: PASS (neutral ESM, no node builtins, signer smoke green)');
}catch(e){console.error('BUNDLE-CHECK: FAIL',e.message);process.exit(1)}
finally{fs.rmSync(tmp,{recursive:true,force:true})}
