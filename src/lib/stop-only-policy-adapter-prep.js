'use strict';
// Stop-only preparation bridge. No default OS capability and no start fallback.
const {createHandleStopExecutor}=require('./handle-stop-executor-prep');
function createStopOnlyPolicyAdapter({store,getReviewedPlan,readActualState,capabilities}){
 if(!store||typeof getReviewedPlan!=='function'||typeof readActualState!=='function'||!capabilities)throw Error('explicit_stop_bridge_required');
 const executor=createHandleStopExecutor({...capabilities,readPersistedIntent:async()=>store.read()});
 return {
  apply:async({action,sessionId,revision,signal})=>{
   if(action!=='ensure-stopped')return {verified:false,error:'start_adapter_not_implemented'};
   const state=store.read();if(state.intent!=='stopped'||state.sessionId!==sessionId||state.revision!==revision)return {verified:false,error:'persisted_stop_intent_required'};
   if(executor.state().busy||executor.state().uncertain)return {verified:false,error:'executor_requires_independent_recovery'};
   const actual=await readActualState({sessionId,signal});if(signal?.aborted)return {verified:false,error:'operation_aborted'};
   if(!actual||actual.verified!==true||actual.sessionId!==sessionId||!['running','stopped'].includes(actual.intent))return {verified:false,error:'actual_state_unbound'};
   if(actual.intent==='stopped')return {verified:true,already:true};
   const plan=await getReviewedPlan({sessionId,signal});if(signal?.aborted)return {verified:false,error:'operation_aborted'};
   return executor.execute({plan,sessionId,revision,signal});
  },
  // Actual state is independently inspected, never copied from desired store intent.
  inspect:async({sessionId,signal})=>{
   const actual=await readActualState({sessionId,signal});
   if(executor.state().busy||executor.state().uncertain)return {verified:false,error:'executor_requires_independent_recovery'};
   if(!actual||actual.verified!==true||actual.sessionId!==sessionId||!['running','stopped'].includes(actual.intent))return {verified:false,error:'actual_state_unbound'};
   return actual;
  },
  state:()=>executor.state()
 };
}
module.exports={createStopOnlyPolicyAdapter};
