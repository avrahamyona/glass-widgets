'use strict';
// Private child-process transport to the native held-handle host. No PID-only stop.
// A native match does not verify commandHash: the executor independently rechecks
// that field against its fresh process snapshot before each action.
const path=require('node:path');
function abortCheck(signal){if(signal?.aborted)throw Error('operation_aborted')}
function cloneIdentity(value){
 const keys=['pid','createdAt','exe','ownerSid','sessionId','commandHash','nativeCreatedFileTimeUtc','logonSid'];
 if(!value||typeof value!=='object')throw Error('native_identity_required');
 const id=Object.fromEntries(keys.map(k=>[k,value[k]]));
 if(!Number.isInteger(id.pid)||id.pid<1||id.pid>0xffffffff||typeof id.createdAt!=='string'||!Number.isFinite(Date.parse(id.createdAt))||typeof id.exe!=='string'||!path.win32.isAbsolute(id.exe)||id.exe.length>32768||!/^S-1-\d+(?:-\d+)+$/.test(id.ownerSid||'')||id.ownerSid.length>184||!/^S-1-5-5-\d+-\d+$/.test(id.logonSid||'')||typeof id.sessionId!=='string'||!id.sessionId.startsWith(id.logonSid+':')||!/^\d+$/.test(id.sessionId.slice(id.logonSid.length+1))||!/^[a-f0-9]{64}$/.test(id.commandHash||'')||typeof id.nativeCreatedFileTimeUtc!=='string'||!/^[1-9][0-9]{0,18}$/.test(id.nativeCreatedFileTimeUtc)||BigInt(id.nativeCreatedFileTimeUtc)>9223372036854775807n)throw Error('native_identity_required');
 return Object.freeze(id);
}
function wireIdentity(id){return {pid:id.pid,nativeCreatedFileTimeUtc:id.nativeCreatedFileTimeUtc,executable:id.exe,ownerSid:id.ownerSid,logonSid:id.logonSid}}
function sameNative(id,wire){const expected=wireIdentity(id);return !!wire&&Object.keys(expected).every(k=>wire[k]===expected[k])}
function createNativeHandleClient({spawnHost,verifyHost,requestTimeoutMs=5000,waitMs=1000}={}){
 if(typeof spawnHost!=='function'||typeof verifyHost!=='function'||!Number.isInteger(requestTimeoutMs)||requestTimeoutMs<20||requestTimeoutMs>30000||!Number.isInteger(waitMs)||waitMs<1||waitMs>30000||waitMs>=requestTimeoutMs)throw Error('explicit_native_transport_required');
 let phase='new',child,buffer='',sequence=0,readyPromise,shutdownPromise,exitInfo,resolveExit;
 const exited=new Promise(resolve=>{resolveExit=resolve}),pending=new Map(),handles=new Set();
 function lose(){
  if(['lost','closed'].includes(phase))return;
  phase='lost';
  for(const p of pending.values()){clearTimeout(p.timer);p.removeAbort();p.reject(Error('native_transport_unverified'))}pending.clear();
  // This is the helper this client spawned, never a discovered process or server.
  try{child?.kill()}catch{}
 }
 function write(packet){
  if(!child||!child.stdin?.writable)throw Error('native_transport_unverified');
  const line=JSON.stringify(packet)+'\n';if(Buffer.byteLength(line)>65536)throw Error('native_packet_too_large');
  child.stdin.write(line,error=>{if(error)lose()});
 }
 function receive(chunk){
  buffer+=chunk;if(Buffer.byteLength(buffer)>131072){lose();return}
  let at;while((at=buffer.indexOf('\n'))>=0){
   const line=buffer.slice(0,at);buffer=buffer.slice(at+1);
   if(Buffer.byteLength(line)>65536){lose();return}
   let packet;try{packet=JSON.parse(line)}catch{lose();return}
   const p=packet&&pending.get(packet.id);
   if(!p||typeof packet.ok!=='boolean'||(packet.ok&&(packet.result===null||typeof packet.result!=='object'))||(!packet.ok&&!/^[a-z_]{1,80}$/.test(packet.error||''))){lose();return}
   pending.delete(packet.id);clearTimeout(p.timer);p.removeAbort();
   if(packet.ok)p.resolve(packet.result);else p.reject(Error(packet.error));
  }
  if(Buffer.byteLength(buffer)>65536)lose();
 }
 function request(op,args={},signal){
  abortCheck(signal);
  if(!['starting','ready','closing'].includes(phase)||phase==='closing'&&op!=='close')return Promise.reject(Error('native_transport_unavailable'));
  if(pending.size>=32)return Promise.reject(Error('native_request_limit'));
  return new Promise((resolve,reject)=>{
   const id=String(++sequence);
   const abort=()=>{try{write({cancel:id})}catch{lose()}};
   const removeAbort=()=>signal?.removeEventListener('abort',abort);
   const timer=setTimeout(lose,requestTimeoutMs);
   pending.set(id,{resolve,reject,timer,removeAbort});
   signal?.addEventListener('abort',abort,{once:true});
   try{write({id,op,...args});if(signal?.aborted)abort()}catch{lose()}
  });
 }
 async function ready(){
  if(phase==='ready')return;
  if(phase!=='new'&&phase!=='starting')throw Error('native_transport_unavailable');
  if(!readyPromise)readyPromise=(async()=>{
   phase='starting';
   if(await verifyHost()!==true)throw Error('native_host_unverified');
   if(phase!=='starting')throw Error('native_transport_unavailable');
   child=await spawnHost();
   if(!child||!child.stdin||!child.stdout||typeof child.on!=='function'||typeof child.kill!=='function')throw Error('native_child_required');
   child.stdout.setEncoding('utf8');child.stdout.on('data',receive);child.stdout.on('error',lose);
   child.stdin.on('error',lose);
   child.stderr?.resume(); // Do not copy raw helper diagnostics into product or test logs.
   child.on('error',lose);
   child.on('close',(code,signal)=>{exitInfo={code,signal};resolveExit(exitInfo);if(phase==='closing'&&pending.size===0&&buffer.length===0&&code===0)phase='closed';else if(phase!=='closed')lose()});
   const result=await request('describe');
   if(result.protocol!==1||result.transport!=='private-stdio'||result.nativePlatform!=='win32'||result.identityTime!=='decimal-filetime-string')throw Error('native_protocol_unverified');
   if(phase!=='starting')throw Error('native_transport_unavailable');phase='ready';
  })().catch(error=>{lose();throw error});
  return readyPromise;
 }
 async function open(value,mayStop,{signal}={}){
  // Copy before the first await, so caller mutation cannot redirect an open.
  const identity=cloneIdentity(value);abortCheck(signal);await ready();abortCheck(signal);
  const result=await request(mayStop?'open-stop':'open-observe',{identity:wireIdentity(identity)},signal);
  if(!/^[a-f0-9]{32}$/.test(result.handle||'')||result.stopCapable!==mayStop||!sameNative(identity,result.identity)){lose();throw Error('native_open_unverified')}
  let closed=false;
  async function close(){
   if(closed)return;closed=true;handles.delete(handle);
   try{const value=await request('close',{handle:result.handle});if(value.closed!==true)throw Error('native_close_unverified')}catch(error){lose();throw error}
  }
  const handle={
   stopCapable:mayStop,
   inspect:async({signal:checkSignal}={})=>{
    if(closed)throw Error('native_handle_closed');abortCheck(checkSignal);
    const value=await request('inspect',{handle:result.handle},checkSignal);abortCheck(checkSignal);
    if(value.verified!==true||typeof value.exited!=='boolean'||!sameNative(identity,value.identity)){lose();throw Error('native_inspection_unverified')}
    return {verified:true,exited:value.exited,identity};
   },close
  };
  if(mayStop){
   let stopRequested=false;
   handle.requestStop=async({signal:stopSignal}={})=>{
    if(closed)throw Error('native_handle_closed');if(stopRequested)throw Error('native_stop_already_requested');abortCheck(stopSignal);
    stopRequested=true;const value=await request('stop',{handle:result.handle},stopSignal);abortCheck(stopSignal);
    if(value.requestAccepted!==true)throw Error('native_stop_unverified');return {requestAccepted:true};
   };
   handle.waitExit=async({signal:waitSignal}={})=>{
    if(closed)throw Error('native_handle_closed');abortCheck(waitSignal);
    const value=await request('wait',{handle:result.handle,waitMs},waitSignal);abortCheck(waitSignal);
    if(typeof value.exited!=='boolean'||value.verified!==value.exited)throw Error('native_exit_unverified');
    return {exited:value.exited,verified:value.verified};
   };
  }
  Object.freeze(handle);handles.add(handle);
  // An open can complete just as cancellation arrives. Close that late handle here.
  if(signal?.aborted){await close();throw Error('operation_aborted')}
  return handle;
 }
 async function dispose(){
  if(shutdownPromise)return shutdownPromise;
  shutdownPromise=(async()=>{
   if(phase==='new'){phase='closed';return {closed:true,verified:true}}
   if(phase==='starting'){try{await readyPromise}catch{}}
   let failed=phase==='lost';if(!failed)phase='closing';
   for(const handle of [...handles])try{await handle.close()}catch{failed=true}
   try{child?.stdin.end()}catch{failed=true}
   if(!child){phase='closed';return {closed:true,verified:!failed}}
   let timer;const end=await Promise.race([exited,new Promise(resolve=>{timer=setTimeout(()=>resolve(null),requestTimeoutMs)})]);clearTimeout(timer);
   if(!end){failed=true;lose();await Promise.race([exited,new Promise(resolve=>setTimeout(resolve,100))])}
   if(end?.code!==0)failed=true;
   return {closed:!!exitInfo,verified:!failed&&phase==='closed'};
  })();return shutdownPromise;
 }
 async function captureObservation({pid,logonSid}={}, {signal}={}){
  if(!Number.isInteger(pid)||pid<1||pid>0x7fffffff||typeof logonSid!=='string'||!/^S-1-5-5-\d+-\d+$/.test(logonSid))throw Error('observation_context_required');
  abortCheck(signal);await ready();abortCheck(signal);
  const value=await request('capture-observation',{pid,logonSid},signal);abortCheck(signal);
  const id=value.identity;
  if(value.verified!==true||value.scope!=='observation-only-not-a-stop-plan'||id?.pid!==pid||id?.logonSid!==logonSid||typeof value.createdAt!=='string'||!Number.isFinite(Date.parse(value.createdAt))||typeof id?.executable!=='string'||!path.win32.isAbsolute(id.executable)||!/^S-1-\d+(?:-\d+)+$/.test(id?.ownerSid||'')||typeof id?.nativeCreatedFileTimeUtc!=='string'||!/^[1-9][0-9]{0,18}$/.test(id.nativeCreatedFileTimeUtc)||BigInt(id.nativeCreatedFileTimeUtc)>9223372036854775807n){lose();throw Error('native_observation_unverified')}
  const fractional=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.(\d{7})Z$/.exec(value.createdAt);
  const unixTicks=BigInt(id.nativeCreatedFileTimeUtc)-116444736000000000n;
  if(!fractional||unixTicks<0n||BigInt(Date.parse(value.createdAt))!==unixTicks/10000n||BigInt(fractional[1].slice(3))!==unixTicks%10000n){lose();throw Error('native_observation_time_unverified')}
  return Object.freeze({pid,createdAt:value.createdAt,exe:id.executable,ownerSid:id.ownerSid,logonSid,nativeCreatedFileTimeUtc:id.nativeCreatedFileTimeUtc,verified:true,scope:value.scope});
 }
 return Object.freeze({ready,captureObservation,openProcess:(id,options)=>open(id,true,options),openReadOnlyProcess:(id,options)=>open(id,false,options),dispose,state:()=>({phase,openHandles:handles.size,pending:pending.size})});
}
module.exports={createNativeHandleClient,cloneIdentity};
