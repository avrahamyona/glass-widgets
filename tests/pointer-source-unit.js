// Pointer-source unit tests: pure candidacy gating of tunnel-state records. No IO.
const{resolvePointer,POINTER_TTL_MS}=require('../server/lib/pointer-source');
const assert=(c,msg)=>{if(!c){console.error('FAIL:',msg);process.exit(1)}};
const DEV='a1b2c3d4e5f60718',URL1='https://words-here-abc123.trycloudflare.com';
const now=1760000000000;
const rec=(o)=>Object.assign({url:URL1,deviceId:DEV,since:new Date(now-10000).toISOString(),down:false},o);

// usable candidate
assert(resolvePointer(rec(),{deviceId:DEV,nowMs:now}).url===URL1,'fresh matching record resolves');
assert(resolvePointer(rec(),{nowMs:now}).url===URL1,'deviceId optional (pre-enrollment bootstrap)');
assert(resolvePointer(rec({since:new Date(now-POINTER_TTL_MS).toISOString()}),{deviceId:DEV,nowMs:now}).url===URL1,'exactly at the ttl boundary still resolves');

// closed gates
assert(resolvePointer(rec({down:true}),{deviceId:DEV,nowMs:now}).reason==='down','down:true closes even when url present');
assert(resolvePointer(rec({url:''}),{deviceId:DEV,nowMs:now}).reason==='down','empty url closes');
assert(resolvePointer(rec({deviceId:'0000000000000000'}),{deviceId:DEV,nowMs:now}).reason==='wrong_device','device mismatch closes');
assert(resolvePointer(rec({url:'https://a-b.trycloudflare.com.evil.example'}),{deviceId:DEV,nowMs:now}).reason==='invalid','lookalike host closes');
assert(resolvePointer(rec({url:'http://words-here-abc123.trycloudflare.com'}),{deviceId:DEV,nowMs:now}).reason==='invalid','http closes');
assert(resolvePointer(rec({since:'not-a-date'}),{deviceId:DEV,nowMs:now}).reason==='invalid','unparsable since closes');
assert(resolvePointer(null,{deviceId:DEV,nowMs:now}).reason==='invalid','null record closes');
assert(resolvePointer([1,2],{deviceId:DEV,nowMs:now}).reason==='invalid','array record closes');

// freshness
assert(resolvePointer(rec({since:new Date(now-POINTER_TTL_MS-1).toISOString()}),{deviceId:DEV,nowMs:now}).reason==='stale','past ttl is stale');
assert(resolvePointer(rec({since:new Date(now+120000).toISOString()}),{deviceId:DEV,nowMs:now}).reason==='stale','far-future timestamp is stale (tamper fails closed)');
assert(resolvePointer(rec({since:new Date(now+10000).toISOString()}),{deviceId:DEV,nowMs:now}).url===URL1,'small clock-skew future tolerated');

console.log('POINTER-SOURCE-UNIT: PASS');
