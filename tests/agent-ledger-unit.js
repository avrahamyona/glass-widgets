// Unit tests for the unified tunnel intake ledger.
const assert=require('assert'),fs=require('fs'),path=require('path');
const {createLedger,RESULT_CAP}=require('../src/lib/ledger.js');
const dir=fs.mkdtempSync('/tmp/gw-ledger-unit-');const F=path.join(dir,'ledger.json');
const now=Date.now();

// lifecycle: accepted -> terminal, terminal is final
let l=createLedger(F);
assert(l.put('cmd-1',{status:'accepted',exp:now+300000})===true,'put accepted');
assert(l.get('cmd-1').status==='accepted','get accepted');
assert(l.put('cmd-1',{status:'done',note:'ok',result:{n:1}})===true,'put terminal');
assert(l.get('cmd-1').terminal===true&&l.get('cmd-1').status==='done','terminal');
assert(l.put('cmd-1',{status:'failed',note:'late'})===true,'terminal rewrite is a no-op true');
assert(l.get('cmd-1').status==='done','terminal never rewritten');
// durability
l=createLedger(F);
assert(l.get('cmd-1').status==='done','survives reload');
// pending expiry policy: an accepted record expires at the envelope exp (prune-on-get)
l=createLedger(F);
assert(l.put('cmd-2',{status:'accepted',exp:now-1000})===true,'already-expired accepted accepted by put');
assert(l.get('cmd-2')===null,'expired accepted pruned on get (sender treats 404 as lost, retries)');
// terminal retention: expiry set to RESULT_TTL on terminal
{const r=l.get('cmd-1');assert(r.exp>now+23*3600*1000,'terminal retained ~24h: '+((r.exp-now)/3600000).toFixed(1)+'h')}
// strict ids: prototype tricks and bad formats rejected
for(const bad of ['__proto__','constructor','a b','x'.repeat(81),'',null,42])assert(l.put(bad,{status:'accepted',exp:now+1000})===false,'bad id refused: '+String(bad));
assert(l.get('__proto__')===null&&!l.has('__proto__'),'proto id never reads');
// result capping: raw payloads never exceed RESULT_CAP in the record
l.put('cmd-3',{status:'done',note:'big',result:{blob:'x'.repeat(RESULT_CAP*3)}});
{const r=l.get('cmd-3');assert(r.result&&r.result.truncated===true&&r.result.full_bytes>RESULT_CAP,'oversize result stored as metadata only: '+JSON.stringify(r.result))}
// caps: MAX_RECORDS eviction, non-terminal first
for(let i=0;i<210;i++)l.put('cmd-x'+i,{status:'accepted',exp:now+300000});
assert(l.get('cmd-1').status==='done','terminal survives accepted-flood eviction');
// strict schema on load: ANY invalid record = store down, and a down store REFUSES writes
fs.writeFileSync(F,JSON.stringify({'cmd-1':{status:'weird',note:'',at:1,exp:now+100000,terminal:false}}));
l=createLedger(F);
assert(l.ok()===false,'invalid record schema -> store down');
assert(l.put('cmd-9',{status:'accepted',exp:now+1000})===false,'put on down store refuses');
fs.writeFileSync(F,'{corrupt');
l=createLedger(F);
assert(l.ok()===false&&l.put('cmd-9',{status:'accepted',exp:now+1000})===false,'corrupt JSON -> down + refuses');
fs.writeFileSync(F,'null');
l=createLedger(F);
assert(l.ok()===false,'null JSON -> down (not a silent fresh store)');
// clean tmp files: no *.tmp litter after successful writes
const tmps=fs.readdirSync(dir).filter(f=>f.includes('.tmp'));
fs.writeFileSync(F,JSON.stringify({}));l=createLedger(F);l.put('a',{status:'accepted',exp:now+1000});
assert(fs.readdirSync(dir).filter(f=>f.includes('.tmp')).length===0,'no tmp litter');
console.log('AGENT-LEDGER-UNIT: PASS');
