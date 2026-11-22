'use strict';
// Start-side bridge. Starting a launcher is never reported as a verified server.
// A policy-aware launcher and independent instance observation are required.
function createStartPolicyAdapter({store,readActualState,getReviewedStartPlan,startManagedServer,localRecoveryReady}={}){
 if(!store||typeof store.read!=='function'||[readActualState,getReviewedStartPlan,startManagedServer,localRecoveryReady].some(f=>typeof f!=='function'))throw Error('explicit_start_capabilities_required');
 function persisted(sessionId,revision){const state=store.read();if(!state||state.intent!=='running'||state.sessionId!==sessionId||state.revision!==revision)throw Error('persisted_start_intent_required')}
 function bound(actual,sessionId,installationId){return actual?.verified===true&&actual.sessionId===sessionId&&actual.installationId===installationId&&['running','stopped'].includes(actual.intent)}
 async function apply({action,sessionId,revision,signal}){
  if(action!=='ensure-running')return {ok:false,error:'start_action_required'};
  let plan;
  try{
   if(signal?.aborted)throw Error('operation_aborted');persisted(sessionId,revision);
   plan=JSON.parse(JSON.stringify(await getReviewedStartPlan({sessionId,revision,signal})));
   if(!plan||plan.verified!==true||plan.policyAware!==true||plan.sessionId!==sessionId||typeof plan.installationId!=='string'||!plan.installationId||!/^[a-f0-9]{64}$/.test(plan.launcherHash||''))throw Error('policy_aware_start_plan_required');
   if(signal?.aborted)throw Error('operation_aborted');
   if(await localRecoveryReady({signal})!==true)throw Error('local_recovery_unverified');
   let actual=await readActualState({sessionId,signal});
   if(!bound(actual,sessionId,plan.installationId))throw Error('actual_state_unbound');
   if(actual.intent==='running')return {verified:true,already:true};
   // Recheck the saved revision immediately before handing off to the launcher.
   // The live capability must enforce the same condition at its commit boundary.
   persisted(sessionId,revision);if(signal?.aborted)throw Error('operation_aborted');
   const result=await startManagedServer({plan,sessionId,revision,signal});
   if(signal?.aborted)throw Error('operation_aborted');
   if(!result||result.accepted!==true)throw Error('start_request_unverified');
   actual=await readActualState({sessionId,signal});
   if(signal?.aborted)throw Error('operation_aborted');persisted(sessionId,revision);
   if(!bound(actual,sessionId,plan.installationId)||actual.intent!=='running')throw Error('started_instance_unverified');
   return {verified:true,installationId:plan.installationId};
  }catch(error){return {ok:false,error:error.message,verified:false};}
 }
 return Object.freeze({apply});
}
module.exports={createStartPolicyAdapter};
