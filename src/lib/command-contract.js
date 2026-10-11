// Shared strict command contract - the SINGLE source for id/kind/reserved-field validation.
// Used by the ledger (ids), the PC verifiers, and the worker signing toolkit. Electron-free.
const ID_RE=/^[\w-]{1,80}$/; // the ledger's id shape (unchanged)
const SIGNER_ID_RE=/^[A-Za-z0-9_-]{8,64}$/; // intentional SUBSET of the ledger's 1-80: worker-issued ids are strictly narrower (UUID and ULID both fit), never wider
const PROTO_IDS=['__proto__','constructor','prototype']; // no prototype tricks, ever
// closed kind allowlist - the PC dispatch table (agent + standalone server skeleton)
const KINDS=new Set(['clipboard_read','delete_file','enroll_device','find_files','get_file','index','island_control','media_control','open_path','read_file','run_command','screenshot','sys_info','ui_automation','update_app','web_task']);
const RESERVED=['id','kind','ts','exp','sig','device','__tunnel']; // envelope/transport fields a data payload may never carry (union of the agent and server guards)
const strictId=id=>typeof id==='string'&&ID_RE.test(id)&&!PROTO_IDS.includes(id); // ledger shape
const signerId=id=>typeof id==='string'&&SIGNER_ID_RE.test(id)&&!PROTO_IDS.includes(id); // worker-issued shape (subset)
function assertKind(kind){if(!KINDS.has(String(kind||'')))throw new Error('kind not allowed')}
function assertNoReserved(data){if(data&&typeof data==='object'&&!Array.isArray(data))for(const k of RESERVED)if(k in data)throw new Error('reserved field in data: '+k)}
function assertTtl(ttlMs){ // explicit integer budget - never a silent NaN/Infinity/fraction
 if(ttlMs==null)return;
 if(!Number.isInteger(ttlMs)||ttlMs<1000||ttlMs>300000)throw new Error('ttl must be an integer 1000..300000 ms');
}
module.exports={ID_RE,SIGNER_ID_RE,PROTO_IDS,KINDS,RESERVED,strictId,signerId,assertKind,assertNoReserved,assertTtl};
