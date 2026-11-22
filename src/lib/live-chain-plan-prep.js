'use strict';
// Pure graph review. Produces an ordered candidate, never stops a process.
// Live adapter must revalidate exact identities immediately before each operation.
const crypto=require('crypto');
const validTime=s=>typeof s==='string'&&Number.isFinite(Date.parse(s));
function identity(p){return {pid:p.pid,createdAt:p.createdAt,exe:p.exe,ownerSid:p.ownerSid,sessionId:p.sessionId,commandHash:p.commandHash,nativeCreatedFileTimeUtc:p.nativeCreatedFileTimeUtc,logonSid:p.logonSid}}
function same(a,b){return ['pid','createdAt','exe','ownerSid','sessionId','commandHash','nativeCreatedFileTimeUtc','logonSid'].every(k=>a[k]===b[k])}
function createdAfter(a,b){
 const native=v=>typeof v==='string'&&/^[1-9][0-9]{0,18}$/.test(v);
 if(native(a.nativeCreatedFileTimeUtc)&&native(b.nativeCreatedFileTimeUtc))return BigInt(a.nativeCreatedFileTimeUtc)>BigInt(b.nativeCreatedFileTimeUtc);
 return Date.parse(a.createdAt)>Date.parse(b.createdAt);
}
function planOwnedChain({processes,reviewed,ownerSid,sessionId}){
 if(!Array.isArray(processes)||!Array.isArray(reviewed)||!reviewed.length||!ownerSid||!sessionId)return {ok:false,error:'reviewed_chain_required'};
 const byPid=new Map();for(const p of processes){if(!p||!Number.isInteger(p.pid)||p.pid<=0||byPid.has(p.pid))return {ok:false,error:'invalid_snapshot'};byPid.set(p.pid,p)}
 const selected=[];
 for(const ref of reviewed){
  const p=byPid.get(ref.pid);if(!p||!same(p,ref)||p.ownerSid!==ownerSid||p.sessionId!==sessionId||!validTime(p.createdAt)||!p.exe||!/^[a-f0-9]{64}$/.test(p.commandHash||''))return {ok:false,error:'identity_unverified'};
  if(!['supervisor','server','tunnel'].includes(ref.role))return {ok:false,error:'role_unverified'};
  selected.push({...identity(p),parentPid:p.parentPid,role:ref.role});
 }
 if(new Set(selected.map(p=>p.pid)).size!==selected.length)return {ok:false,error:'duplicate_reviewed_process'};
 const roles=role=>selected.filter(p=>p.role===role);
 const supervisors=roles('supervisor'),servers=roles('server'),tunnels=roles('tunnel');
 if(supervisors.length<1||supervisors.length>2||servers.length!==1||tunnels.length>1)return {ok:false,error:'unexpected_chain_shape'};
 const server=servers[0],tunnel=tunnels[0];
 // CALL may run both command-file loops in one cmd host. Review process identities,
 // not script count. Accept one or two verified supervisor hosts in an actual chain.
 const ordered=[];let cursor=server;
 while(ordered.length<supervisors.length){const parent=supervisors.find(p=>p.pid===cursor.parentPid&&!ordered.some(x=>x.pid===p.pid));if(!parent)return {ok:false,error:'parent_chain_unverified'};ordered.push(parent);cursor=parent}
 ordered.reverse();
 if(tunnel&&tunnel.parentPid!==server.pid)return {ok:false,error:'parent_chain_unverified'};
 for(const p of selected){const parent=byPid.get(p.parentPid);if(parent&&createdAfter(parent,p))return {ok:false,error:'parent_pid_reused'}}
 const ids=new Set(selected.map(p=>p.pid));
 for(const p of processes)if(ids.has(p.parentPid)&&!ids.has(p.pid))return {ok:false,error:'unreviewed_child'};
 // Stop respawners first, then tunnel, then server. A disabled policy must be persisted first.
 const steps=[...ordered,...(tunnel?[tunnel]:[]),server].map(p=>({operation:'stop-exact-owned-instance',identity:identity(p),role:p.role,verifyExit:true}));
 return {ok:true,steps,requiresPersistedStopIntent:true,requiresLocalRecovery:true,execute:false,
  planHash:crypto.createHash('sha256').update(JSON.stringify(steps)).digest('hex')};
}
function revalidateStep(step,fresh){return !!step&&!!fresh&&same(step.identity,fresh)}
module.exports={planOwnedChain,revalidateStep,createdAfter};
