// Packaging dependency boundary: the installed artifact packs ONLY src/**/* (+ build/tray.png),
// so a RELATIVE require that escapes src/ resolves in the checkout but breaks module resolution
// in the built app. Scan every src/**/*.js for relative requires and assert each one resolves
// INSIDE src/ (bare specifiers = node builtins / declared dependencies, both packed by the builder).
const fs=require('fs'),path=require('path');
const SRC=path.join(__dirname,'..','src');
const REQ_RE=/require\(\s*'([^']+)'\s*\)|require\(\s*"([^"]+)"\s*\)/g;
let files=0,bad=[];
(function walk(d){for(const f of fs.readdirSync(d)){const p=path.join(d,f);const st=fs.statSync(p);
 if(st.isDirectory())walk(p);
 else if(f.endsWith('.js')){files++;
  const s=fs.readFileSync(p,'utf8');let m;
  while((m=REQ_RE.exec(s))){const spec=m[1]||m[2];
   if(!spec.startsWith('.'))continue; // bare: builtin or declared dependency
   const resolved=path.resolve(path.dirname(p),spec);
   if(!(resolved===SRC||resolved.startsWith(SRC+path.sep)))bad.push(path.relative(SRC,p)+' -> '+spec);}}}})(SRC);
if(bad.length){console.error('PACK-DEPS: FAIL - relative requires escaping the packed src/ tree:');for(const b of bad)console.error('  '+b);process.exit(1)}
console.log('PACK-DEPS: PASS ('+files+' src files, every relative require resolves inside the packed tree)');
