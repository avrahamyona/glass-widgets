// Fixture tests for the owner-only ACL evaluator (PowerShell Get-Acl JSON shape).
const assert=require('assert');
const {evalAclDump,FULL_CONTROL}=require('../src/lib/acl-check.js');
const ME='S-1-5-21-1004336348-1177238915-682003330-51213';
const READ_WRITE=0x1301BF&FULL_CONTROL; // Read|Write subset within FullControl
const rule=(o={})=>({sid:ME,rights:READ_WRITE,allow:true,inherited:false,...o});
const dump=(o={})=>({me:ME,protected:true,owner:ME,rules:[rule()],...o});
// happy path
assert(evalAclDump(dump(),ME)===true,'single owner-only Allow rule, protected DACL, expected owner passes');
assert(evalAclDump(dump({rules:rule()}),ME)===true,'single rule as bare object (ConvertTo-Json shape) passes');
assert(evalAclDump(dump({rules:[rule({rights:FULL_CONTROL})]}),ME)===true,'owner FullControl passes');
// multi-ACE fixtures (the ops-reproduced SYSTEM+user case)
assert(evalAclDump(dump({rules:[rule({sid:'S-1-5-18'}),rule()]}),ME)===false,'SYSTEM + user (2 ACEs) -> false');
assert(evalAclDump(dump({rules:[rule(),rule({sid:'S-1-5-32-545'})]}),ME)===false,'user + Users group (2 ACEs) -> false');
// rule fields
assert(evalAclDump(dump({rules:[rule({allow:false})]}),ME)===false,'Deny rule -> false');
assert(evalAclDump(dump({rules:[rule({inherited:true})]}),ME)===false,'inherited ACE -> false');
assert(evalAclDump(dump({rules:[(r=>{delete r.inherited;return r})(rule())]}),ME)===false,'MISSING inherited flag -> false (explicit false required)');
assert(evalAclDump(dump({rules:[rule({sid:'S-1-5-21-1-2-3-9999'})]}),ME)===false,'different SID -> false');
assert(evalAclDump(dump({rules:[rule({sid:ME+' '})]}),ME)===false,'SID with trailing space -> false');
// rights bounds (32-bit bitwise smuggling)
assert(evalAclDump(dump({rules:[rule({rights:0x100000000})]}),ME)===false,'rights above 2^32 -> false (no bitwise smuggling)');
assert(evalAclDump(dump({rules:[rule({rights:FULL_CONTROL+1})]}),ME)===false,'rights above FullControl -> false');
assert(evalAclDump(dump({rules:[rule({rights:-1})]}),ME)===false,'negative rights -> false');
assert(evalAclDump(dump({rules:[rule({rights:1.5})]}),ME)===false,'non-integer rights -> false');
assert(evalAclDump(dump({rules:[rule({rights:'576'}),]}),ME)===false,'string rights -> false');
// dump-level fields
assert(evalAclDump(dump({protected:false}),ME)===false,'unprotected DACL (inherited ACEs possible) -> false');
assert(evalAclDump(dump({owner:'S-1-5-18'}),ME)===false,'wrong owner SID -> false');
assert(evalAclDump(dump({me:'S-1-5-18'}),ME)===false,'dump resolved under a DIFFERENT identity -> false');
assert(evalAclDump(null,ME)===false,'null dump -> false');
assert(evalAclDump({},ME)===false,'empty dump -> false');
assert(evalAclDump(dump({rules:'text'}),ME)===false,'non-array rules -> false');
console.log('AGENT-ACL-UNIT: PASS');
