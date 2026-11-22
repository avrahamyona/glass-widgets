'use strict';
// Coordinates injected capabilities only. No default network, files, processes or UI.
// Adapter implementations still require separate review and Windows rehearsal.
function createLiveCoordinator({store,getSession,adapter,deadlineMs=5000}){
 if(!store||typeof getSession!=='function'||!adapter||!Number.isFinite(deadlineMs)||deadlineMs<1)throw Error('reviewed_adapters_required');
 let q=Promise.resolve(),uncertain=false;
 async function bounded(fn){let timer;const ac=new AbortController();try{return await Promise.race([Promise.resolve().then(()=>fn(ac.signal)),new Promise((_,reject)=>{timer=setTimeout(()=>{ac.abort();reject(Error('adapter_timeout'))},deadlineMs)})])}finally{clearTimeout(timer)}}
 const serialize=fn=>{const p=q.then(fn);q=p.catch(()=>{});return p};
 async function act(event){
  if(uncertain)return {ok:false,error:'prior_action_unverified',requiresReconciliation:true};
  const session=await bounded(()=>getSession()),old=store.read();
  const decision=store.transition({event,currentSessionId:session.sessionId,expectedRevision:old.revision});
  if(!decision.ok)return decision;
  // Atomic persisted intent MUST precede planning a live action, especially manual stop.
  if(decision.persisted!==true)throw Error('intent_not_persisted');
  try{
   const result=await bounded(signal=>adapter.apply({action:decision.action,sessionId:session.sessionId,revision:decision.next.revision,signal}));
   if(!result||result.verified!==true){uncertain=true;return {ok:false,error:'result_unverified',persistedIntent:decision.next.intent,requiresReconciliation:true}}
   return {ok:true,verified:true,intent:decision.next.intent};
  }catch{uncertain=true;return {ok:false,error:'action_failed_or_timed_out',persistedIntent:decision.next.intent,requiresReconciliation:true}}
 }
 return {
  request:event=>serialize(()=>act(event)),
  reconcile:()=>serialize(async()=>{
   // Reconciliation is read-only. It never clears a manual stop or replays an uncertain action.
   const session=await bounded(()=>getSession()),state=store.read();
   if(state.sessionId!==session.sessionId)return {ok:false,error:'session_changed'};
   const r=await bounded(signal=>adapter.inspect({sessionId:session.sessionId,signal}));
   if(r&&r.verified===true&&r.intent===state.intent){uncertain=false;return {ok:true,verified:true}}
   return {ok:false,error:'state_still_unverified',requiresReconciliation:true};
  }),
  state:()=>({uncertain})
 };
}
module.exports={createLiveCoordinator};
