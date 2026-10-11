// Fixture tests for the owner-only ACL evaluator (PowerShell Get-Acl JSON shape).
const assert=require('assert');
const {evalAclDump,FULL_CONTROL}=require('../src/lib/acl-check.js');
const ME='S-1-5-21-1004336348-1177238915-682003330-51213';
const READ_WRITE=0x1301BF&FULL_CONTROL; // Read|Write subset within FullControl
const rule=(o={})=>({sid:ME,rights:READ_WRITE,allow:true,inherited:false,...o});
// the ops-reproduced shape: first ACE carried alongside the filepath must NOT be dropped -
// with JSON input there is no text line to misparse, but two rules must still fail.
assert(evalAclDump({me:ME,rules:[rule()]},ME)===true,'single owner-only Allow rule passes');
assert(evalAclDump({me:ME,rules:[rule({sid:'S-1-5-18'}),rule()]},ME)===false,'SYSTEM + user (2 ACEs) -> false');
assert(evalAclDump({me:ME,rules:[rule(),rule({sid:'S-1-5-32-545'})]},ME)===false,'user + Users group (2 ACEs) -> false');
assert(evalAclDump({me:ME,rules:[rule({allow:false})]},ME)===false,'Deny rule -> false');
assert(evalAclDump({me:ME,rules:[rule({inherited:true})]},ME)===false,'inherited ACE -> false');
assert(evalAclDump({me:ME,rules:[rule({sid:'S-1-5-21-1-2-3-9999'})]},ME)===false,'different SID -> false');
assert(evalAclDump({me:ME,rules:[rule({rights:0x10000000})]},ME)===false,'GENERIC_ALL (beyond FullControl) -> false');
assert(evalAclDump({me:ME,rules:[rule({rights:FULL_CONTROL})]},ME)===true,'owner FullControl passes');
assert(evalAclDump({me:ME,rules:[rule({rights:FULL_CONTROL|0x10000000})]},ME)===false,'FullControl + generic bit -> false');
// ConvertTo-Json emits a bare OBJECT when there is exactly one rule
assert(evalAclDump({me:ME,rules:rule()},ME)===true,'single rule as bare object (ConvertTo-Json shape) passes');
// localized/garbled output never reaches here as valid JSON; malformed dumps fail closed
assert(evalAclDump(null,ME)===false,'null dump -> false');
assert(evalAclDump({},ME)===false,'empty dump -> false');
assert(evalAclDump({me:'S-1-5-18',rules:[rule()]},ME)===false,'dump resolved under a DIFFERENT identity -> false');
assert(evalAclDump({me:ME,rules:'text'},ME)===false,'non-array rules -> false');
assert(evalAclDump({me:ME,rules:[{sid:ME+' ',rights:READ_WRITE,allow:true,inherited:false}]},ME)===false,'SID with trailing space (substring tricks) -> false');
console.log('AGENT-ACL-UNIT: PASS');
