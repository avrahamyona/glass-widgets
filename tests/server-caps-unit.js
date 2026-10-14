// A4: capabilities derive from the real op registry (one source of truth), the mapping refuses
// unknown kinds, and a forged/wider advertisement can never widen the executable set.
const assert=require('assert');
const{OPS}=require('../server/lib/ops');
const{deriveCaps,capsAllowKind,KIND_CAP}=require('../server/lib/capabilities');
// derivation from the REAL registry
const caps=deriveCaps(OPS);
assert(caps==='exec,files,sys','caps derive from the registry, got: '+caps);
// every registered op has a declared capability - no orphan kinds
for(const k of Object.keys(OPS))assert(KIND_CAP[k],'op without a capability mapping: '+k);
// routing predicate
assert(capsAllowKind(caps,'find_files')&&capsAllowKind(caps,'read_file')&&capsAllowKind(caps,'write_file'),'advertised kinds allowed');
assert(!capsAllowKind(caps,'shell'),'unknown kind refused');
assert(!capsAllowKind('', 'find_files'),'empty advertisement refuses');
assert(!capsAllowKind('sig,ui','read_file'),'kind outside the advertised caps refused');
// a FORGED wider advertisement widens NOTHING: the predicate is only as broad as KIND_CAP
assert(!capsAllowKind('files,admin,shell','shell'),'forged caps cannot conjure a kind');
// a registry extension automatically re-derives (no hand-edited banner to forget)
const extended=Object.assign(Object.create(null),OPS,{delete_file:async()=>({ok:true})}); // delete_file is deliberately NOT in KIND_CAP (and must never be)
KIND_CAP; // mapping lives in the shared module - an unmapped new op stays unadvertised
assert(deriveCaps(extended)==='exec,files,sys','an op without a KIND_CAP entry is not advertised (fail closed)');
// and is refused by the predicate even though it exists in the registry
assert(!capsAllowKind(deriveCaps(extended),'delete_file'),'unmapped op refused by the predicate');
console.log('SERVER-CAPS-UNIT: PASS');
