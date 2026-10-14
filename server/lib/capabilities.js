// A4 capabilities (standalone server side): the caps string a server advertises is DERIVED from
// its actual op registry - one source of truth, no hand-maintained banner. The advertisement is
// INFORMATIONAL ONLY: it travels under the baked, public command key and grants NOTHING by
// itself (docs/worker-integration-plan.md A4). Authority comes from the device-signed
// registration; the worker routes only kinds the device advertised, and this module is the
// single mapping both sides can share.
const KIND_CAP=Object.freeze({ // command kind -> the capability that covers it
 find_files:'files',
 read_file:'files',
 write_file:'files',
 enroll_device:'enroll', // the bootstrap op - always pre-enrollment capable
});
// deriveCaps(OPS) -> sorted unique csv of capabilities the registry can actually serve.
function deriveCaps(OPS){
 const caps=new Set();
 for(const k of Object.keys(OPS||{})){const c=KIND_CAP[k];if(c)caps.add(c)}
 return [...caps].sort().join(',');
}
// capsAllowKind(capsCsv,kind) -> would this advertisement cover the kind? Unknown kinds and
// kinds outside the advertised caps are refused. A FORGED advertisement changes nothing on the
// device side: execution authority stays with the signed envelope + the local op registry.
function capsAllowKind(capsCsv,kind){
 const c=KIND_CAP[String(kind||'')];
 if(!c)return false;
 return String(capsCsv||'').split(',').includes(c);
}
module.exports={KIND_CAP,deriveCaps,capsAllowKind};
