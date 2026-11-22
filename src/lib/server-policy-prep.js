'use strict';
// Pure policy planner. Adapter must supply verified Windows logon-session identity,
// private atomic persistence and per-user synchronization. This module performs no I/O.
// App relaunch/update is NOT a Windows logon. Unknown/corrupt state never means Start.
const POLICY='login-start-manual-stop-until-next-login-v1';
const validSession=s=>typeof s==='string'&&s.length>=1&&s.length<=160&&/^[A-Za-z0-9_.:-]+$/.test(s);
function validState(s){return s&&s.version===1&&s.policy===POLICY&&validSession(s.sessionId)&&['running','stopped'].includes(s.intent)&&Number.isSafeInteger(s.revision)&&s.revision>=0}
function plan({event,currentSessionId,persisted}){
 if(!validSession(currentSessionId))return {ok:false,error:'verified_logon_session_required',action:'none'};
 if(!validState(persisted))return {ok:false,error:'reviewed_policy_state_required',action:'none'};
 if(!['windows-logon','app-open','recover','manual-start','manual-stop'].includes(event))return {ok:false,error:'unknown_event',action:'none'};
 const changed=currentSessionId!==persisted.sessionId;
 // Only a verified logon event or an explicit manual command may cross sessions.
 // App-open and automatic recovery must not invent a logon event.
 if(changed&&!['windows-logon','manual-start','manual-stop'].includes(event))return {ok:false,error:'logon_transition_not_verified',action:'none'};
 let intent=changed?'running':persisted.intent;
 if(event==='manual-start')intent='running';
 if(event==='manual-stop')intent='stopped';
 if(persisted.revision===Number.MAX_SAFE_INTEGER)return {ok:false,error:'revision_exhausted',action:'none'};
 const next={version:1,policy:POLICY,sessionId:currentSessionId,intent,revision:persisted.revision+1};
 return {ok:true,action:intent==='running'?'ensure-running':'ensure-stopped',next,
  expectedRevision:persisted.revision,persistBeforeAction:true,requiresAtomicCompareAndSet:true,
  resetsManualStop:changed&&persisted.intent==='stopped'&&intent==='running'};
}
function initialState({currentSessionId,explicitInstallationApproved}){
 if(explicitInstallationApproved!==true||!validSession(currentSessionId))return {ok:false,error:'installation_approval_and_verified_logon_required'};
 return {ok:true,state:{version:1,policy:POLICY,sessionId:currentSessionId,intent:'running',revision:0},applied:false};
}
module.exports={POLICY,plan,initialState};
