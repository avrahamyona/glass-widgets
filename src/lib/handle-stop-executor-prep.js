'use strict';
// Process-handle protocol executor. Injected capabilities only, no native process access.
// This module is NOT a Windows implementation and grants no execution permission.
const {revalidateStep}=require('./live-chain-plan-prep');
const crypto=require('crypto');
const {observationDigest}=require('./auxiliary-chain-plan-prep');
function createHandleStopExecutor({openProcess,openReadOnlyProcess,readSnapshot,readPersistedIntent,localRecoveryReady,deadlineMs=5000}){
 if([openProcess,readSnapshot,readPersistedIntent,localRecoveryReady].some(f=>typeof f!=='function')||!Number.isInteger(deadlineMs)||deadlineMs<1)throw Error('explicit_capabilities_required');
 let busy=false,uncertain=false;
 function interrupted(signal){if(signal.aborted)throw Error('operation_aborted')}
 async function execute({plan,sessionId,revision,signal:parentSignal}){
  if(busy)return {ok:false,error:'executor_busy'};
  if(uncertain)return {ok:false,error:'prior_stop_unverified',requiresReconciliation:true};
  if(!plan||plan.ok!==true||!Array.isArray(plan.steps)||!plan.steps.length||!sessionId||!Number.isInteger(revision))return {ok:false,error:'verified_plan_required'};
  // Freeze the reviewed value before the first await. Caller mutations cannot redirect work.
  try{plan=JSON.parse(JSON.stringify(plan))}catch{return {ok:false,error:'verified_plan_required'}}
  if(plan.steps.some(s=>s.operation!=='stop-exact-owned-instance'||s.verifyExit!==true||!s.identity||s.identity.sessionId!==sessionId)||new Set(plan.steps.map(s=>s.identity.pid)).size!==plan.steps.length)return {ok:false,error:'invalid_stop_steps'};
  const roles=plan.steps.map(s=>s.role);if(!/^supervisor(,supervisor)?(,tunnel)?,server$/.test(roles.join(','))||plan.requiresPersistedStopIntent!==true||plan.requiresLocalRecovery!==true||plan.execute!==false||plan.planHash!==crypto.createHash('sha256').update(JSON.stringify(plan.steps)).digest('hex'))return {ok:false,error:'plan_integrity_failed'};
  const aux=plan.observedAuxiliaries||[];
  if(!Array.isArray(aux)||aux.length>16||aux.some(a=>a.role!=='observe-only'||a.sessionId!==sessionId)||new Set([...plan.steps.map(s=>s.identity.pid),...aux.map(a=>a.pid)]).size!==plan.steps.length+aux.length||(aux.length&&(typeof openReadOnlyProcess!=='function'||plan.observationHash!==observationDigest(plan.steps,aux))))return {ok:false,error:'auxiliary_plan_unverified'};
  busy=true;const handles=[],stopped=[];let actionIssued=false,timer;
  const ac=new AbortController(),abort=()=>ac.abort();if(parentSignal){parentSignal.addEventListener('abort',abort,{once:true});if(parentSignal.aborted)ac.abort()}
  const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{ac.abort();reject(Error('operation_timeout'))},deadlineMs)});
  async function preconditions(){
   interrupted(ac.signal);
   if(await localRecoveryReady({signal:ac.signal})!==true)throw Error('local_recovery_unverified');
   interrupted(ac.signal);
   const state=await readPersistedIntent({signal:ac.signal});interrupted(ac.signal);
   if(!state||state.intent!=='stopped'||state.sessionId!==sessionId||state.revision!==revision)throw Error('persisted_stop_intent_required');
  }
  async function inspectAll(){
   interrupted(ac.signal);const snapshot=await readSnapshot({signal:ac.signal});interrupted(ac.signal);
   if(!Array.isArray(snapshot))throw Error('snapshot_unverified');
   const seen=new Set();for(const p of snapshot){if(!p||!Number.isInteger(p.pid)||seen.has(p.pid))throw Error('snapshot_unverified');seen.add(p.pid)}
   const ids=new Set([...plan.steps.map(s=>s.identity.pid),...aux.map(a=>a.pid)]);
   for(const p of snapshot)if(ids.has(p.parentPid)&&!ids.has(p.pid))throw Error('unreviewed_child');
   for(const {step,handle,observeOnly} of handles){
    const state=await handle.inspect({signal:ac.signal});interrupted(ac.signal);
    if(!state||state.verified!==true||!revalidateStep(step,state.identity))throw Error('handle_identity_unverified');
    const row=snapshot.find(p=>p.pid===step.identity.pid);
    if(observeOnly){
     if(state.exited===true){if(row)throw Error('auxiliary_pid_reappeared')}
     else if(!row||!revalidateStep(step,row)||row.parentPid!==step.parentPid)throw Error('auxiliary_changed');
    }else if(stopped.includes(step.identity.pid)){
     if(state.exited!==true)throw Error('exit_verification_lost');
     // A reused PID is never an owned process. Refuse instead of following it.
     if(row)throw Error('stopped_pid_reappeared');
    }else if(state.exited===true||!row||!revalidateStep(step,row))throw Error('process_changed');
   }
  }
  const work=async()=>{
   await preconditions();
   // Hold all verified native handles before any side effect. No PID-only fallback.
   for(const step of plan.steps){
    interrupted(ac.signal);const handle=await openProcess(step.identity,{signal:ac.signal});
    if(!handle||['inspect','requestStop','waitExit','close'].some(k=>typeof handle[k]!=='function')){try{await handle?.close?.()}catch{}throw Error('verified_handle_required')}
    handles.push({step,handle});interrupted(ac.signal);
   }
   for(const a of aux){
    interrupted(ac.signal);const handle=await openReadOnlyProcess(a,{signal:ac.signal});
    if(!handle||handle.stopCapable!==false||typeof handle.requestStop==='function'||['inspect','close'].some(k=>typeof handle[k]!=='function')){try{await handle?.close?.()}catch{}throw Error('read_only_auxiliary_handle_required')}
    handles.push({step:{identity:a,parentPid:a.parentPid},handle,observeOnly:true});interrupted(ac.signal);
   }
   await inspectAll();
   for(const {step,handle} of handles.filter(h=>!h.observeOnly)){
    await preconditions();await inspectAll();interrupted(ac.signal);
    // requestStop must synchronously recheck abort and target only its held handle.
    actionIssued=true;const stop=await handle.requestStop({signal:ac.signal});interrupted(ac.signal);
    if(!stop||stop.requestAccepted!==true)throw Error('stop_request_unverified');
    const exit=await handle.waitExit({signal:ac.signal});interrupted(ac.signal);
    if(!exit||exit.exited!==true||exit.verified!==true)throw Error('owned_exit_unverified');
    stopped.push(step.identity.pid);
   }
   await inspectAll();return {ok:true,verified:true,stoppedCount:stopped.length,scope:'injected-handle-protocol-only'};
  };
  // Cleanup is inside the work promise: even a capability that returns after timeout
  // must close a late handle. Busy stays set until that work has actually settled.
  const settled=work().finally(async()=>{
   for(const {handle} of [...handles].reverse())try{await handle.close()}catch{uncertain=true}
   busy=false;
  });
  try{const result=await Promise.race([settled,deadline]);return uncertain&&result.ok?{ok:false,error:'handle_cleanup_unverified',requiresReconciliation:true,scope:'injected-handle-protocol-only'}:result}
  catch(e){if(actionIssued)uncertain=true;return {ok:false,error:e.message,stoppedCount:stopped.length,requiresReconciliation:uncertain,scope:'injected-handle-protocol-only'}}
  finally{clearTimeout(timer);ac.abort();if(parentSignal)parentSignal.removeEventListener('abort',abort)}
 }
 return {execute,state:()=>({busy,uncertain})};
}
module.exports={createHandleStopExecutor};
