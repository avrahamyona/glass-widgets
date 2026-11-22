'use strict';
// Runs only on the approved public CI branch. All stop targets are created below.
// No real server, chat data, listener, installed application or account is used.
const assert=require('node:assert/strict'),cp=require('node:child_process'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createNativeHandleClient}=require('../src/lib/native-handle-client-prep');
const {createWindowsSessionReader}=require('../src/lib/windows-session-reader-prep');
const {createPolicyStore}=require('../src/lib/server-policy-store-prep');
const {initialState}=require('../src/lib/server-policy-prep');
const {createOperationJournal}=require('../src/lib/server-operation-journal-prep');
const {createIntegratedServerControl}=require('../src/lib/integrated-server-control-prep');
const {planWithAuxiliaries}=require('../src/lib/auxiliary-chain-plan-prep');
const {registerServerControlIpc}=require('../src/lib/server-control-ipc-prep');
const {pathToFileURL}=require('node:url');
if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_REPOSITORY!=='avrahamyona/glass-widgets'||process.env.GITHUB_REF!=='refs/heads/validation/receive-native-20261122')throw Error('isolated_windows_ci_only');
const root=path.resolve(__dirname,'..'),host=path.join(root,'native','ServerControlHost','ci-publish','ServerControlHost.exe'),fixture=path.join(__dirname,'fixtures','ci-owned-server-graph.cjs');
const hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const hostHash=hash(host),fixtureHash=hash(fixture),nativeHash=hash(path.join(root,'native','ServerControlPrep','VerifiedProcessHandle.cs'));
assert.equal(nativeHash,'acc1783f6d54cdb4385918fdb9faa93252e6298460525b925a12bcd33e0588f0');
const ps=path.win32.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe'),icacls=path.win32.join(process.env.SystemRoot,'System32','icacls.exe');
const ciReadTimeoutMs=15000;
const exec=(exe,args,extra={})=>new Promise((resolve,reject)=>{const started=Date.now();cp.execFile(exe,args,{windowsHide:true,shell:false,encoding:'utf8',timeout:ciReadTimeoutMs,maxBuffer:2*1024*1024,...extra},(error,out,stderr)=>{if(error){console.log(JSON.stringify({ciReadFailed:true,elapsedMs:Date.now()-started,killed:error.killed===true,exitCode:Number.isInteger(error.code)?error.code:null,moduleLoadReported:/CouldNotAutoloadMatchingModule|could not be loaded/i.test(String(stderr))}));reject(Error('ci_read_command_failed'))}else resolve(String(out))})});
const sessionExec=(exe,args,options,done)=>{const started=Date.now(),query=path.win32.basename(exe).toLowerCase()==='whoami.exe'?'logon':'boot';return cp.execFile(exe,args,{...options,timeout:ciReadTimeoutMs},(error,out,stderr)=>{console.log(JSON.stringify({sessionQuery:query,elapsedMs:Date.now()-started,ok:!error,killed:error?.killed===true,exitCode:Number.isInteger(error?.code)?error.code:null,moduleLoadReported:/CouldNotAutoloadMatchingModule|could not be loaded/i.test(String(stderr))}));done(error,out,stderr)})};
const psJson=async(script,extraEnv={})=>JSON.parse(await exec(ps,['-NoProfile','-NonInteractive','-Command',script],{env:{...process.env,...extraEnv}}));
const parentScript="@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object { @{pid=[uint32]$_.ProcessId;parentPid=[uint32]$_.ParentProcessId} }) | ConvertTo-Json -Compress";
const childNameScript="$ErrorActionPreference='Stop';$id=[uint32]$env:GW_CI_PID;$rows=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$id) -Property Name);if($rows.Count -ne 1){throw 'fixture_child_changed'};[string]$rows[0].Name | ConvertTo-Json -Compress";
const commandHashScript="$ErrorActionPreference='Stop';$id=[uint32]$env:GW_CI_PID;$rows=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$id) -Property CommandLine);if($rows.Count -ne 1 -or [string]::IsNullOrWhiteSpace($rows[0].CommandLine)){throw 'fixture_command_unavailable'};$sha=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$rows[0].CommandLine))).Replace('-','').ToLowerInvariant()) | ConvertTo-Json -Compress}finally{$sha.Dispose()}";
const aclScript="$ErrorActionPreference='Stop';$a=[IO.Directory]::GetAccessControl($env:GW_CI_DIR);$allowed=@($env:GW_CI_OWNER,'S-1-5-18','S-1-5-32-544');$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));$bad=@($rules | Where-Object { $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -notcontains $_.IdentityReference.Value });[bool]($a.AreAccessRulesProtected -and ($allowed -contains $a.GetOwner([Security.Principal.SecurityIdentifier]).Value) -and $bad.Count -eq 0) | ConvertTo-Json -Compress";
let client,control,dir,session,ownerSid,graph,store,journal,stage='bootstrap';
const mark=value=>{stage=value;console.log('owned-ci stage '+value)};
const graphs=[],trace=[];
const clientFactory=()=>createNativeHandleClient({verifyHost:()=>hash(host)===hostHash,spawnHost:()=>cp.spawn(host,[],{windowsHide:true,stdio:['pipe','pipe','pipe'],shell:false}),requestTimeoutMs:7000,waitMs:1500});
function verifyPrivateDirectory(candidate){
 if(candidate!==dir||!fs.lstatSync(candidate).isDirectory()||fs.lstatSync(candidate).isSymbolicLink())return false;
 try{return JSON.parse(cp.execFileSync(ps,['-NoProfile','-NonInteractive','-Command',aclScript],{windowsHide:true,shell:false,encoding:'utf8',timeout:5000,maxBuffer:4096,env:{...process.env,GW_CI_DIR:dir,GW_CI_OWNER:ownerSid}}))===true}catch{return false}
}
async function actual(){
 if(!graph)return {verified:true,intent:'stopped',sessionId:session.sessionId,installationId:'ci-owned-'+nonce};
 const states=await Promise.all(graph.observers.map(handle=>handle.inspect()));
 if(states.every(state=>state.exited))return {verified:true,intent:'stopped',sessionId:session.sessionId,installationId:'ci-owned-'+nonce};
 if(states.every(state=>state.verified&&!state.exited))return {verified:true,intent:'running',sessionId:session.sessionId,installationId:'ci-owned-'+nonce};
 return {verified:false};
}
async function snapshot(){
 const rows=await psJson(parentScript);if(!Array.isArray(rows)||rows.some(r=>!Number.isInteger(r.pid)||!Number.isInteger(r.parentPid)))throw Error('parent_snapshot_unverified');
 const ids=new Map();
 for(let index=0,all=[...graph.identities,...graph.auxiliaries],observers=[...graph.observers,...graph.auxObservers];index<all.length;index++){
  const id=all[index],observer=observers[index],before=await observer.inspect();
  if(before.exited)continue;
  const commandHash=await psJson(commandHashScript,{GW_CI_PID:String(id.pid)});
  const after=await observer.inspect();if(after.exited||!/^[a-f0-9]{64}$/.test(commandHash))throw Error('fixture_snapshot_changed');
  ids.set(id.pid,{...id,commandHash});
 }
 return rows.map(row=>ids.has(row.pid)?{...ids.get(row.pid),parentPid:row.parentPid}:row);
}
const nonce=crypto.randomUUID();
async function startGraph(){
 assert.equal(hash(fixture),fixtureHash);
 const child=cp.spawn(process.execPath,[fixture,'supervisor'],{stdio:['ignore','ignore','pipe','ipc'],windowsHide:true,shell:false,env:{...process.env,GW_OWNED_FIXTURE_NONCE:nonce}});
 child.stderr.resume();
 const record={child,identities:[],observers:[],auxiliaries:[],auxObservers:[],metadata:null};graphs.push(record);
 mark('graph-handshake');const metadata=await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(Error('fixture_handshake_timeout')),10000);
  child.once('error',()=>{clearTimeout(timer);reject(Error('fixture_spawn_failed'))});
  child.on('message',value=>{if(value?.kind==='owned-graph'&&value.nonce===nonce&&value.supervisorPid===child.pid&&Number.isInteger(value.serverPid)&&value.serverPid>0){clearTimeout(timer);resolve(value)}});
  child.once('exit',()=>{clearTimeout(timer);reject(Error('fixture_exited_before_handshake'))});
 });record.metadata=metadata;
 for(const [pid,role]of [[metadata.supervisorPid,'supervisor'],[metadata.serverPid,'server']]){
  mark('capture-'+role);const captured=await client.captureObservation({pid,logonSid:session.sessionId.slice(0,session.sessionId.lastIndexOf(':'))});
  assert.equal(captured.ownerSid,ownerSid);assert.equal(captured.exe.toLowerCase(),process.execPath.toLowerCase());
  const commandHash=await psJson(commandHashScript,{GW_CI_PID:String(pid)});
  assert.match(commandHash,/^[a-f0-9]{64}$/);
  const id={...captured,sessionId:session.sessionId,commandHash,role};record.identities.push(id);
  const observer=await client.openReadOnlyProcess(id);record.observers.push(observer);
  assert.equal(observer.requestStop,undefined);
 }
 graph=record;mark('capture-console-auxiliaries');
 const raw=await psJson(parentScript),stopIds=new Set(record.identities.map(id=>id.pid));
 const candidates=raw.filter(row=>stopIds.has(row.parentPid)&&!stopIds.has(row.pid));assert(candidates.length<=4);
 const consolePath=path.win32.join(process.env.SystemRoot,'System32','conhost.exe');
 for(const candidate of candidates){
  const captured=await client.captureObservation({pid:candidate.pid,logonSid:session.sessionId.slice(0,session.sessionId.lastIndexOf(':'))});
  assert.equal(captured.ownerSid,ownerSid);assert.equal(captured.exe.toLowerCase(),consolePath.toLowerCase());
  const parent=record.identities.find(id=>id.pid===candidate.parentPid);assert(parent);assert(BigInt(parent.nativeCreatedFileTimeUtc)<=BigInt(captured.nativeCreatedFileTimeUtc));
  const commandHash=await psJson(commandHashScript,{GW_CI_PID:String(candidate.pid)});assert.match(commandHash,/^[a-f0-9]{64}$/);
  const id={...captured,parentPid:candidate.parentPid,sessionId:session.sessionId,commandHash,role:'observe-only',reason:'Windows console host of a CI-owned dummy process'};
  const observer=await client.openReadOnlyProcess(id);assert.equal(observer.requestStop,undefined);assert.equal(observer.waitExit,undefined);
  record.auxiliaries.push(id);record.auxObservers.push(observer);
 }
 mark('initial-parent-snapshot');const rows=await snapshot();
 for(const auxiliary of record.auxiliaries){const fresh=rows.find(row=>row.pid===auxiliary.pid);assert(fresh);assert.equal(fresh.parentPid,auxiliary.parentPid)}
 for(const id of record.identities){const row=rows.find(p=>p.pid===id.pid);assert(row);id.parentPid=row.parentPid}
 assert.equal(record.identities[1].parentPid,record.identities[0].pid);
 return {accepted:true};
}
function ipcFor(value){
 const handlers=new Map(),file=path.join(root,'src','server-settings','index.html'),url=pathToFileURL(file).href,frame={url},contents={mainFrame:frame,isDestroyed:()=>false,getURL:()=>url};
 registerServerControlIpc({ipcMain:{handle:(key,fn)=>handlers.set(key,fn),removeHandler:key=>handlers.delete(key)},getManagementWindow:()=>({isDestroyed:()=>false,webContents:contents}),settingsFile:file,control:value});
 return method=>handlers.get('server:'+method)({sender:contents,senderFrame:frame});
}
async function cleanup(){
 let verified=true;
 for(const record of graphs){
  if(record.child.connected){
   try{record.child.send({kind:'cleanup-owned-graph',nonce})}catch{}
   await Promise.race([new Promise(resolve=>record.child.once('exit',resolve)),new Promise(resolve=>setTimeout(resolve,2000))]);
  }
  // Stop only exact identities captured from our own graph, never PID-only fallback.
  for(let index=0;index<record.identities.length;index++){
   const id=record.identities[index],observer=record.observers[index];let h;
   try{
    if(observer&&(await observer.inspect()).exited)continue;
    h=await client.openProcess(id);await h.requestStop();if(!(await h.waitExit()).exited)verified=false;
   }catch{verified=false}finally{if(h)try{await h.close()}catch{verified=false}}
  }
  for(const observer of record.auxObservers){try{let ended=false;for(let attempt=0;attempt<20;attempt++){if((await observer.inspect()).exited){ended=true;break}await new Promise(resolve=>setTimeout(resolve,50))}if(!ended)verified=false}catch{verified=false}}
  for(const observer of [...record.observers,...record.auxObservers])try{await observer.close()}catch{verified=false}
  if(record.child.exitCode===null&&record.child.signalCode===null)verified=false;
 }
 if(control){const closed=await control.dispose();if(!closed.verified)verified=false}
 else if(client){const closed=await client.dispose();if(!closed.verified)verified=false}
 if(dir){try{fs.rmSync(dir,{recursive:true,force:true})}catch{verified=false}if(fs.existsSync(dir))verified=false}
 return verified;
}
(async()=>{
 let result,cleanupVerified=false;
 try{
  mark('native-handshake');client=clientFactory();await client.ready();mark('windows-session-observation');session=await createWindowsSessionReader({execFile:sessionExec})();
  mark('actor-observation');const self=await client.captureObservation({pid:process.pid,logonSid:session.sessionId.slice(0,session.sessionId.lastIndexOf(':'))});ownerSid=self.ownerSid;
  mark('private-directory');assert(process.env.RUNNER_TEMP&&path.isAbsolute(process.env.RUNNER_TEMP));dir=fs.mkdtempSync(path.join(process.env.RUNNER_TEMP,'gw-owned-integration-'));
  cp.execFileSync(icacls,[dir,'/inheritance:r','/grant:r','*'+ownerSid+':(OI)(CI)F','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],{windowsHide:true,shell:false,stdio:'pipe',timeout:5000});
  assert(verifyPrivateDirectory(dir));
  store=createPolicyStore({dir,verifyPrivateDirectory});journal=createOperationJournal({dir,verifyPrivateDirectory});
  store.initialize(initialState({currentSessionId:session.sessionId,explicitInstallationApproved:true}).state,{installationApproved:true});
  const nativeProxy={...client,openProcess:async(id,options)=>{
   assert.equal(store.read().intent,'stopped');trace.push({kind:'open',pid:id.pid});
   const h=await client.openProcess(id,options);return {...h,requestStop:async args=>{assert.equal(store.read().intent,'stopped');trace.push({kind:'stop',pid:id.pid});return h.requestStop(args)}};
  }};
  control=createIntegratedServerControl({store,journal,nativeClient:nativeProxy,installationId:'ci-owned-'+nonce,getSession:async()=>session,readActualState:actual,
   getReviewedStopPlan:async()=>{const rows=await snapshot(),plan=planWithAuxiliaries({processes:rows,reviewed:graph.identities,auxiliaries:graph.auxiliaries,ownerSid,sessionId:session.sessionId}),ids=new Set([...graph.identities,...graph.auxiliaries].map(id=>id.pid));console.log(JSON.stringify({ownedStopPlan:plan.ok===true,error:/^[a-z_]{1,100}$/.test(plan.error||'')?plan.error:null,stepCount:plan.steps?.length||0,directUnreviewedChildren:rows.filter(row=>ids.has(row.parentPid)&&!ids.has(row.pid)).length}));for(const child of rows.filter(row=>ids.has(row.parentPid)&&!ids.has(row.pid)).slice(0,4)){try{const name=String(await psJson(childNameScript,{GW_CI_PID:String(child.pid)})).toLowerCase();console.log(JSON.stringify({unreviewedDirectChildKind:['conhost.exe','openconsole.exe'].includes(name)?name:'other'}))}catch{console.log(JSON.stringify({unreviewedChildDiagnosticUnavailable:true}))}}return {...plan,installationId:'ci-owned-'+nonce}},
   getReviewedStartPlan:async()=>({verified:true,policyAware:true,installationId:'ci-owned-'+nonce,sessionId:session.sessionId,launcherHash:fixtureHash}),
   startManagedServer:async({plan,revision,signal})=>{assert(!signal.aborted);assert.equal(plan.launcherHash,hash(fixture));assert.equal(store.read().revision,revision);assert.equal(store.read().intent,'running');return startGraph()},
   readSnapshot:snapshot,localRecoveryReady:async()=>true,deadlineMs:30000});
  const invoke=ipcFor(control);
  mark('owned-start');assert((await invoke('start')).verified);assert.equal((await invoke('status')).running,true);
  const first=graph.identities[0];
  mark('wrong-tick-refusal');await assert.rejects(client.openProcess({...first,nativeCreatedFileTimeUtc:String(BigInt(first.nativeCreatedFileTimeUtc)+1n)}),/native_process_identity_changed/);
  assert.equal((await graph.observers[0].inspect()).exited,false);
  mark('real-wait-cancellation');const waitingHandle=await client.openProcess(first),ac=new AbortController();
  const waiting=waitingHandle.waitExit({signal:ac.signal});setTimeout(()=>ac.abort(),100);
  await assert.rejects(waiting,/operation_aborted/);assert.equal((await waitingHandle.inspect()).exited,false);await waitingHandle.close();
  mark('integrated-stop');const stopped=await invoke('stop');console.log(JSON.stringify({ownedStopVerified:stopped.verified===true,ownedStopError:stopped.error||null,controller:control.state(),controllerNativeOpens:trace.filter(row=>row.kind==='open').length,controllerStops:trace.filter(row=>row.kind==='stop').length,journalKind:journal.load().kind}));assert(stopped.verified);
  assert.equal(store.read().intent,'stopped');assert.equal(journal.load().kind,'none');
  assert.deepEqual(trace.filter(e=>e.kind==='stop').map(e=>e.pid),graph.identities.map(p=>p.pid));
  assert((await graph.observers[0].inspect()).exited);assert((await graph.observers[1].inspect()).exited);
  const count=trace.length;assert((await control.appOpen()).verified);assert.equal(trace.length,count);assert.equal((await invoke('status')).running,false);
  result={nativeHostCompiled:true,privateWindowsDirectoryVerified:true,exactNativeIdentityCaptured:true,wrongNativeTickRefused:true,cancellationDeliveredDuringRealWait:true,ownedStartObserved:true,stopIntentPersistedBeforeControllerHandleOpen:true,ownedGraphStoppedInOrder:true,consoleHelpersObserveOnly:true,observedConsoleHelperCount:graph.auxiliaries.length,manualStopSurvivedAppReopen:true,scope:'CI-owned Node dummy graph and real native held handles; IPC origin harness only',productionLauncher:false,installedUi:false,realAnswerEndToEnd:false};
 }finally{cleanupVerified=await cleanup();console.log(JSON.stringify({ownedCleanupVerified:cleanupVerified}))}
 assert(cleanupVerified,'owned_fixture_cleanup_unverified');
 console.log(JSON.stringify({...result,cleanupVerified}));
})().catch(error=>{console.error(JSON.stringify({failedStage:stage,error:/^[a-z_]{1,100}$/.test(error.message||'')?error.message:'check_failed_at_named_stage',productionOrUserPcAction:false}));process.exitCode=1});
