'use strict';
// Pure reviewed graph extension. Auxiliary processes are observed, never stop targets.
const {planOwnedChain,revalidateStep,createdAfter}=require('./live-chain-plan-prep'),crypto=require('crypto');
const digest=(steps,aux)=>crypto.createHash('sha256').update(JSON.stringify({steps,aux})).digest('hex');
function planWithAuxiliaries({processes,reviewed,auxiliaries,ownerSid,sessionId}){
 if(!Array.isArray(auxiliaries)||auxiliaries.length>16||!Array.isArray(processes)||!Array.isArray(reviewed))return {ok:false,error:'explicit_auxiliaries_required'};
 const stopIds=new Set(reviewed.map(p=>p.pid)),auxIds=new Set();
 for(const a of auxiliaries){
  if(!a||a.role!=='observe-only'||!a.reason||typeof a.reason!=='string'||a.reason.length>160||auxIds.has(a.pid)||stopIds.has(a.pid))return {ok:false,error:'invalid_auxiliary'};
  const matches=processes.filter(p=>p.pid===a.pid),p=matches[0];
  if(matches.length!==1||!revalidateStep({identity:a},p)||p.parentPid!==a.parentPid||p.ownerSid!==ownerSid||p.sessionId!==sessionId||!Number.isFinite(Date.parse(p.createdAt))||!/^[a-f0-9]{64}$/.test(p.commandHash||''))return {ok:false,error:'auxiliary_identity_unverified'};
  auxIds.add(a.pid);
 }
 const allIds=new Set([...stopIds,...auxIds]);
 for(const a of auxiliaries){let cursor=a;const visited=new Set();while(!stopIds.has(cursor.parentPid)){
  if(visited.has(cursor.pid))return {ok:false,error:'auxiliary_cycle'};visited.add(cursor.pid);cursor=auxiliaries.find(p=>p.pid===cursor.parentPid);if(!cursor)return {ok:false,error:'auxiliary_parent_unverified'};
 }
 const parent=processes.find(p=>p.pid===a.parentPid);if(!parent||createdAfter(parent,a))return {ok:false,error:'auxiliary_parent_reused'};
 }
 for(const p of processes)if(allIds.has(p.parentPid)&&!allIds.has(p.pid))return {ok:false,error:'unreviewed_child'};
 const base=planOwnedChain({processes:processes.filter(p=>!auxIds.has(p.pid)),reviewed,ownerSid,sessionId});if(!base.ok)return base;
 const aux=auxiliaries.map(p=>({pid:p.pid,parentPid:p.parentPid,createdAt:p.createdAt,exe:p.exe,ownerSid:p.ownerSid,sessionId:p.sessionId,commandHash:p.commandHash,nativeCreatedFileTimeUtc:p.nativeCreatedFileTimeUtc,logonSid:p.logonSid,role:'observe-only',reason:p.reason}));
 return {...base,observedAuxiliaries:aux,observationHash:digest(base.steps,aux)};
}
module.exports={planWithAuxiliaries,observationDigest:digest};
