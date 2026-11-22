'use strict';
// One connection point for application commands, policy, persistence and native
// handle transport. All live OS observations and managed-start actions are explicit
// capabilities. No initialization, legacy launcher fallback or startup mutation.
const crypto=require('node:crypto');
const {createLiveCoordinator}=require('./live-coordinator-prep');
const {createStopOnlyPolicyAdapter}=require('./stop-only-policy-adapter-prep');
const {createStartPolicyAdapter}=require('./start-policy-adapter-prep');
function createIntegratedServerControl({store,journal,nativeClient,installationId,getSession,readActualState,getReviewedStopPlan,getReviewedStartPlan,startManagedServer,readSnapshot,localRecoveryReady,verifyLogonSource,deadlineMs=5000}={}){
 if(!store||!journal||!nativeClient||typeof installationId!=='string'||!installationId||[getSession,readActualState,getReviewedStopPlan,getReviewedStartPlan,startManagedServer,readSnapshot,localRecoveryReady].some(f=>typeof f!=='function'))throw Error('integrated_control_capabilities_required');
 const controllerId=crypto.randomUUID();let busy=false,closed=false,applyCalls=0,lastFailure=null;
 function barrierPresent(){try{return journal.load().kind!=='none'}catch{return true}}
 async function boundedRead(fn){const ac=new AbortController();let timer;try{return await Promise.race([Promise.resolve().then(()=>fn(ac.signal)),new Promise((_,reject)=>{timer=setTimeout(()=>{ac.abort();reject(Error('control_read_timeout'))},deadlineMs)})])}finally{clearTimeout(timer)}}
 const boundActual=async options=>{
  const actual=await readActualState(options);
  return actual?.verified===true&&actual.installationId===installationId&&actual.sessionId===options.sessionId&&['running','stopped'].includes(actual.intent)?actual:{verified:false,error:'actual_state_unbound'};
 };
 const stop=createStopOnlyPolicyAdapter({store,readActualState:boundActual,getReviewedPlan:async options=>{
  const plan=await getReviewedStopPlan(options);
  return plan?.installationId===installationId?plan:{ok:false,error:'stop_plan_unbound'};
 },capabilities:{openProcess:nativeClient.openProcess,openReadOnlyProcess:nativeClient.openReadOnlyProcess,readSnapshot,localRecoveryReady,deadlineMs}});
 const start=createStartPolicyAdapter({store,readActualState:boundActual,getReviewedStartPlan,startManagedServer,localRecoveryReady});
 const adapter={apply:async input=>{applyCalls++;return input.action==='ensure-stopped'?stop.apply(input):input.action==='ensure-running'?start.apply(input):{verified:false,error:'unknown_action'}},inspect:stop.inspect};
 const coordinator=createLiveCoordinator({store,getSession,adapter,deadlineMs:deadlineMs+100});
 async function request(event){
  if(closed)return {ok:false,error:'control_closed'};
  if(busy)return {ok:false,error:'control_busy'};
  if(!['manual-start','manual-stop','app-open','recover','windows-logon'].includes(event))return {ok:false,error:'unknown_event'};
  busy=true;let token;const before=applyCalls;
  try{
   const state=store.read();token=journal.begin({controllerId,event,installationId,persistedSessionId:state.sessionId});
   const result=await coordinator.request(event);
   // A policy refusal before entering an adapter cannot have issued an OS action.
   // An entered but unverified adapter leaves the durable barrier in place.
   if(result?.verified===true||applyCalls===before)journal.complete(token);
   if(result?.verified!==true)lastFailure=result?.error||'control_result_unverified';
   return {...result,durableBarrier:barrierPresent()};
  }catch(error){
   if(token&&applyCalls===before)try{journal.complete(token)}catch{}
   lastFailure=/^[a-z_]{1,80}$/.test(error.message||'')?error.message:'control_failed';
   return {ok:false,error:lastFailure,requiresReconciliation:true,durableBarrier:barrierPresent()};
  }finally{busy=false}
 }
 async function status(){
  if(closed)return {ok:false,provisioned:false,running:null,error:'control_closed'};
  try{
   const {actual}=await boundedRead(async signal=>{const session=await getSession({signal});return {actual:await boundActual({sessionId:session.sessionId,signal})}}),barrier=journal.load();
   const verified=actual.verified===true;
   return {ok:verified,verified,provisioned:true,running:verified?actual.intent==='running':null,desiredIntent:store.read().intent,blocked:barrier.kind!=='none',inProgress:busy,requiresReconciliation:barrier.kind!=='none'||coordinator.state().uncertain,error:verified?null:actual.error||'actual_state_unverified'};
  }catch{return {ok:false,verified:false,provisioned:true,running:null,error:'control_status_unverified',requiresReconciliation:true}}
 }
 return Object.freeze({
  status,start:()=>request('manual-start'),stop:()=>request('manual-stop'),appOpen:()=>request('app-open'),recover:()=>request('recover'),
  windowsLogon:async evidence=>{try{return typeof verifyLogonSource==='function'&&await boundedRead(()=>verifyLogonSource(evidence))===true?request('windows-logon'):{ok:false,error:'verified_logon_source_required'}}catch{return {ok:false,error:'verified_logon_source_unavailable'}}},
  // Intentionally no automatic barrier reset. Cross-restart cleanup and quiescence
  // need independent OS proof before a live recovery command can be added.
  dispose:async()=>{closed=true;return nativeClient.dispose()},
  state:()=>({busy,closed,lastFailure,uncertain:coordinator.state().uncertain,executor:stop.state(),native:nativeClient.state()})
 });
}
module.exports={createIntegratedServerControl};
