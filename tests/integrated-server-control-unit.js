'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const {createPolicyStore}=require('../src/lib/server-policy-store-prep');
const {initialState}=require('../src/lib/server-policy-prep');
const {createOperationJournal}=require('../src/lib/server-operation-journal-prep');
const {createNativeHandleClient}=require('../src/lib/native-handle-client-prep');
const {planWithAuxiliaries}=require('../src/lib/auxiliary-chain-plan-prep');
const {createIntegratedServerControl}=require('../src/lib/integrated-server-control-prep');
const {registerServerControlIpc}=require('../src/lib/server-control-ipc-prep');
const {pathToFileURL}=require('node:url');
function ipcFor(control){const handlers=new Map(),file=path.join(__dirname,'..','src','server-settings','index.html'),url=pathToFileURL(file).href,frame={url},contents={mainFrame:frame,isDestroyed:()=>false,getURL:()=>url};registerServerControlIpc({ipcMain:{handle:(channel,fn)=>handlers.set(channel,fn),removeHandler:channel=>handlers.delete(channel)},getManagementWindow:()=>({isDestroyed:()=>false,webContents:contents}),settingsFile:file,control});return method=>handlers.get('server:'+method)({sender:contents,senderFrame:frame})}
const fixture=path.join(__dirname,'fixtures','native-host-protocol-fixture.cjs');
function environment(options={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gw-integrated-control-')),events=path.join(dir,'native-events.jsonl'),installationId='test-owned-installation';
 const privateFixture=p=>p===dir; // Fixture only. Not a Windows ACL assertion.
 const store=createPolicyStore({dir,verifyPrivateDirectory:privateFixture});
 let session='S-1-5-5-10-20:1795284000000',round=1,active=options.initiallyStopped!==true,launches=0,controls=[];
 const eventProof=Object.freeze({source:'test-owned-logon-event'});
 store.initialize(initialState({currentSessionId:session,explicitInstallationApproved:true}).state,{installationApproved:true});
 const readEvents=()=>fs.existsSync(events)?fs.readFileSync(events,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
 function graph(){
  const logonSid=session.slice(0,session.lastIndexOf(':')),base=round*100;
  const item=(offset,parentPid,role)=>({pid:base+offset,parentPid,role,createdAt:'2026-11-21T17:07:19.6976620Z',exe:'C:\\Fixture\\owned.exe',ownerSid:'S-1-5-21-100-100-100-1000',logonSid,sessionId:session,commandHash:String(offset+1).repeat(64),nativeCreatedFileTimeUtc:String(134397544396976621n+BigInt(base+offset))});
  const reviewed=[item(0,1,'supervisor'),item(1,base,'server'),item(2,base+1,'tunnel')],auxiliaries=[{...item(3,base,'observe-only'),reason:'test-owned observed helper'}];
  return {reviewed,auxiliaries,ownerSid:reviewed[0].ownerSid,sessionId:session,processes:[...reviewed,...auxiliaries]};
 }
 function snapshot(){if(!active)return [];const exited=new Set(readEvents().filter(e=>e.op==='owned-exit').map(e=>e.pid));return graph().processes.filter(p=>!exited.has(p.pid))}
 async function actual({sessionId}){
  if(options.unboundActual)return {verified:true,installationId:'foreign-installation',sessionId,intent:'running'};
  const live=new Set(snapshot().map(p=>p.pid)),targets=graph().reviewed,alive=targets.filter(p=>live.has(p.pid)).length;
  if(alive!==0&&alive!==targets.length)return {verified:false};
  return {verified:true,installationId,sessionId,intent:alive?'running':'stopped'};
 }
 function makeControl(){
  const nativeClient=createNativeHandleClient({verifyHost:()=>true,spawnHost:()=>cp.spawn(process.execPath,[fixture,options.mode||'normal',events],{stdio:['pipe','pipe','pipe'],shell:false,env:{}}),requestTimeoutMs:500,waitMs:50});
  const control=createIntegratedServerControl({store,journal:createOperationJournal({dir,verifyPrivateDirectory:privateFixture}),nativeClient,installationId,getSession:async()=>({sessionId:session}),readActualState:actual,
   getReviewedStopPlan:async()=>{const g=graph();return {...planWithAuxiliaries({...g,processes:snapshot()}),installationId}},
   getReviewedStartPlan:async()=>({verified:true,policyAware:true,installationId,sessionId:session,launcherHash:'f'.repeat(64)}),
   startManagedServer:async({revision,sessionId,signal})=>{assert(!signal.aborted);assert.equal(store.read().intent,'running');assert.equal(store.read().sessionId,sessionId);assert.equal(store.read().revision,revision);launches++;if(!options.acceptOnly){round++;active=true}return {accepted:true}},
   readSnapshot:async()=>snapshot(),localRecoveryReady:async()=>options.recovery!==false,verifyLogonSource:async proof=>proof===eventProof,deadlineMs:1000});
  controls.push(control);return control;
 }
 return {store,makeControl,events:readEvents,snapshot,launches:()=>launches,nextSession:()=>{session='S-1-5-5-11-21:1795284000000'},eventProof,journal:()=>createOperationJournal({dir,verifyPrivateDirectory:privateFixture}),clean:async()=>{for(const c of controls)await c.dispose();fs.rmSync(dir,{recursive:true,force:true})}};
}
(async()=>{
 let n=0;async function test(name,fn){await fn();n++;console.log('ok '+name)}
 await test('IPC -> policy -> atomic store -> coordinator -> planner -> native client -> real child stdio',async()=>{const f=environment();try{const c=f.makeControl();const invoke=ipcFor(c);const r=await invoke('stop');assert(r.verified);assert.equal(f.store.read().intent,'stopped');assert.equal(f.journal().load().kind,'none');assert.deepEqual(f.events().filter(e=>e.op==='termination-request').map(e=>e.pid),[100,102,101]);assert.equal(f.events().filter(e=>e.op==='closed').length,4);assert(!f.events().some(e=>e.op==='termination-request'&&e.pid===103));assert.equal((await c.status()).running,false)}finally{await f.clean()}});
 await test('app reopen keeps manual stop and does not reopen handles or invoke launcher',async()=>{const f=environment();try{let c=f.makeControl();assert((await c.stop()).verified);const count=f.events().length;assert((await c.appOpen()).verified);assert.equal(f.events().length,count);await c.dispose();c=f.makeControl();assert((await c.appOpen()).verified);assert.equal(f.store.read().intent,'stopped');assert.equal(f.launches(),0);assert.equal(c.state().native.phase,'new')}finally{await f.clean()}});
 await test('explicit start persists first, independently verifies the new instance, then can stop it',async()=>{const f=environment({initiallyStopped:true});try{const c=f.makeControl();const r=await c.start();assert(r.verified);assert.equal(f.launches(),1);assert.equal(f.store.read().intent,'running');assert.equal((await c.status()).running,true);assert((await c.stop()).verified);assert.deepEqual(f.events().filter(e=>e.op==='termination-request').map(e=>e.pid),[200,202,201])}finally{await f.clean()}});
 await test('launcher acceptance alone leaves intent but keeps a durable uncertainty barrier',async()=>{const f=environment({initiallyStopped:true,acceptOnly:true});try{const c=f.makeControl();assert(!(await c.start()).ok);assert.equal(f.store.read().intent,'running');assert.equal(f.journal().load().kind,'pending');assert.equal((await c.status()).running,false);assert.equal((await c.start()).error,'prior_operation_requires_review');assert.equal(f.launches(),1)}finally{await f.clean()}});
 await test('uncertain native exit blocks replay even after a new controller is created',async()=>{const f=environment({mode:'no-exit'});try{let c=f.makeControl();assert(!(await c.stop()).ok);assert.equal(f.store.read().intent,'stopped');assert.equal(f.journal().load().kind,'pending');assert.deepEqual(f.events().filter(e=>e.op==='termination-request').map(e=>e.pid),[100]);await c.dispose();c=f.makeControl();assert.equal((await c.appOpen()).error,'prior_operation_requires_review');assert.equal(c.state().native.phase,'new');assert.equal((await c.status()).requiresReconciliation,true);assert.equal((await c.status()).running,true)}finally{await f.clean()}});
 await test('only a separately verified logon source resets stop automatically',async()=>{const f=environment();try{const c=f.makeControl();assert((await c.stop()).verified);f.nextSession();assert.equal((await c.appOpen()).error,'logon_transition_not_verified');assert.equal(f.launches(),0);assert.equal((await c.windowsLogon({source:'forged'})).error,'verified_logon_source_required');assert((await c.windowsLogon(f.eventProof)).verified);assert.equal(f.launches(),1);assert.equal(f.store.read().intent,'running')}finally{await f.clean()}});
 await test('explicit Start remains available in a newly verified session without inventing a logon event',async()=>{const f=environment();try{const c=f.makeControl();assert((await c.stop()).verified);f.nextSession();assert((await c.start()).verified);assert.equal(f.store.read().intent,'running');assert.equal(f.launches(),1)}finally{await f.clean()}});
 await test('unbound observation is unknown, never a false stopped status or a native action',async()=>{const f=environment({unboundActual:true});try{const c=f.makeControl();assert.equal((await c.status()).running,null);assert(!(await c.stop()).ok);assert.equal(c.state().native.phase,'new');assert.equal(f.events().length,0)}finally{await f.clean()}});
 await test('missing local recovery blocks native opens',async()=>{const f=environment({recovery:false});try{const c=f.makeControl();assert(!(await c.stop()).ok);assert.equal(f.events().length,0);assert.equal(f.store.read().intent,'stopped')}finally{await f.clean()}});
 await test('journal is a cross-controller mutex and corrupt records are not silently removed',async()=>{const f=environment();try{const j=f.journal(),record=j.begin({controllerId:'11111111-1111-4111-8111-111111111111',event:'manual-stop',installationId:'test-owned-installation',persistedSessionId:f.store.read().sessionId});assert.throws(()=>j.begin({...record}),/prior_operation_requires_review/);assert.throws(()=>j.complete({...record,nonce:'22222222-2222-4222-8222-222222222222'}),/operation_token_changed/);assert.equal(j.load().kind,'pending');j.complete(record);assert.equal(j.load().kind,'none')}finally{await f.clean()}});
 console.log(JSON.stringify({checks:n,scope:'integrated real policy/store/journal/planner/coordinator/client and child-process IPC',osCapabilities:'fixture',managedStart:'injected fixture',nativeWindowsExecution:false,applicationUiInstalled:false}));
})().catch(error=>{console.error(error);process.exitCode=1});
