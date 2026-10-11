// Pure evaluation of a PowerShell Get-Acl JSON dump for owner-only verification.
// Electron-free by design so tests/agent-acl-unit.js can drive it with fixtures on any platform.
// The dump comes from: (Get-Acl -LiteralPath <p>).Access projected to
// {me, rules:[{sid,rights,allow,inherited}]} (see agent.js ACL_PS).
const FULL_CONTROL=2032127; // 0x1F01FF - every right the owner may hold is within this mask
function evalAclDump(dump,meSid){
 if(!dump||typeof dump!=='object')return false;
 if(String(dump.me)!==String(meSid))return false; // the dump itself must resolve the same identity
 let rules=dump.rules;
 if(rules&&!Array.isArray(rules))rules=[rules]; // ConvertTo-Json emits a bare object for ONE rule
 if(!Array.isArray(rules)||rules.length!==1)return false; // exactly one ACE, no more
 const r=rules[0];
 if(String(r.sid)!==String(meSid))return false; // exact SID match - never a username substring
 if(r.allow!==true)return false; // Allow only - a Deny or mixed entry fails
 if(r.inherited===true)return false; // no inherited ACEs (inheritance was stripped)
 if(typeof r.rights!=='number'||(r.rights&~FULL_CONTROL)!==0)return false; // no rights beyond FullControl (e.g. GENERIC_ALL)
 return true;
}
module.exports={evalAclDump,FULL_CONTROL};
