// Pointer resolution for the tunnel-first sender (Efi pattern): decide whether a tunnel-state
// record - from ANY rendezvous (local tunnel-state.json content relayed to the sender, or a
// worker discovery body adapted to the same shape) - is a usable candidate deviceUrl.
//
// The pointer is PUBLIC and untrusted: this module only gates candidacy (shape, device match,
// freshness). What AUTHENTICATES the endpoint is unchanged: the /health?nonce= device-key
// proof at connect time, then signed envelopes / signed reads (docs/sender-tunnel-contract.md).
// A wrong/stale pointer therefore fails closed - never a silent fall to an impostor.
const{validateTunnelUrl}=require('../../src/lib/tunnel');
const POINTER_TTL_MS=90000; // the contract's stale window: no heartbeat within 90s (or down:true) = stale
const SKEW_MS=30000; // small future tolerance for clock skew; beyond it a future-dated record fails closed too

function resolvePointer(rec,{deviceId,nowMs,ttlMs}={}){
 if(!rec||typeof rec!=='object'||Array.isArray(rec))return{url:null,reason:'invalid'};
 if(rec.down===true||!rec.url)return{url:null,reason:'down'}; // explicit clear wins over everything
 if(deviceId!=null&&String(rec.deviceId)!==String(deviceId))return{url:null,reason:'wrong_device'};
 if(validateTunnelUrl(rec.url)!==rec.url)return{url:null,reason:'invalid'}; // quick-tunnel exact host ONLY - a rendezvous pointing elsewhere fails closed
 const since=Date.parse(rec.since||'');
 if(!Number.isFinite(since))return{url:null,reason:'invalid'};
 const now=nowMs==null?Date.now():nowMs,ttl=ttlMs==null?POINTER_TTL_MS:ttlMs;
 if(now-since>ttl)return{url:null,reason:'stale'};
 if(since-now>SKEW_MS)return{url:null,reason:'stale'}; // far-future timestamps are tamper/damage evidence, not freshness
 return{url:rec.url};
}

module.exports={resolvePointer,POINTER_TTL_MS,SKEW_MS};
