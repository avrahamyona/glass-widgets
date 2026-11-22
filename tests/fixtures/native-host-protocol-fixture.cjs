'use strict';
// Test-owned protocol fixture. Never included in the production host or invoked by app code.
const readline=require('node:readline'),fs=require('node:fs');
const mode=process.argv[2]||'normal',events=process.argv[3],open=new Map(),cancelled=new Set();let next=0;
const log=data=>{if(events)fs.appendFileSync(events,JSON.stringify(data)+'\n')};
const send=(id,result)=>process.stdout.write(JSON.stringify({id,ok:true,result})+'\n');
const fail=(id,error)=>process.stdout.write(JSON.stringify({id,ok:false,error})+'\n');
const input=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
input.on('line',async line=>{
 const q=JSON.parse(line);
 if(q.cancel){cancelled.add(q.cancel);log({op:'cancel',id:q.cancel});return}
 log({op:q.op,id:q.id,pid:q.identity?.pid,handle:q.handle});
 if(mode==='hang'&&q.op==='open-stop')return;
 if(q.op==='describe'){send(q.id,{protocol:1,transport:'private-stdio',nativePlatform:'win32',identityTime:'decimal-filetime-string'});return}
 if(q.op==='capture-observation'){
  send(q.id,{verified:true,scope:'observation-only-not-a-stop-plan',createdAt:mode==='wrong-capture-time'?'2026-11-21T17:07:19.6976620Z':'2026-11-21T17:07:19.6976621Z',identity:{pid:q.pid,nativeCreatedFileTimeUtc:'134397544396976621',executable:'C:\\Fixture\\owned.exe',ownerSid:'S-1-5-21-100-100-100-1000',logonSid:q.logonSid}});return;
 }
 if(mode==='death'&&q.op==='open-stop'){process.exit(7);return}
 if(mode==='malformed'&&q.op==='open-stop'){process.stdout.write('broken\n');return}
 if(q.op==='open-stop'||q.op==='open-observe'){
  if(mode==='late-open')await new Promise(resolve=>setTimeout(resolve,50));
  const key=(++next).toString(16).padStart(32,'0'),entry={identity:q.identity,stop:q.op==='open-stop',exited:false};open.set(key,entry);
  if(mode==='server-exits-before-stop'&&q.op==='open-stop'&&q.identity.pid%100===1){entry.exited=true;log({op:'owned-exit',pid:entry.identity.pid})}
  let identity=entry.identity;if(mode==='wrong-ticks')identity={...identity,nativeCreatedFileTimeUtc:String(BigInt(identity.nativeCreatedFileTimeUtc)+1n)};
  log({op:'opened',handle:key,pid:entry.identity.pid});send(q.id,{handle:key,stopCapable:entry.stop,identity});return;
 }
 const entry=open.get(q.handle);if(!entry){fail(q.id,'unknown_handle');return}
 if(q.op==='inspect'){send(q.id,{verified:true,exited:entry.exited,identity:entry.identity});return}
 if(q.op==='stop'){
  if(!entry.stop){fail(q.id,'observation_handle_cannot_stop');return}
  if(entry.requested){fail(q.id,'termination_already_requested');return}
  entry.requested=true;log({op:'termination-request',pid:entry.identity.pid});send(q.id,{requestAccepted:true});return;
 }
 if(q.op==='wait'){
  if(mode==='wait-abort'){
   const timer=setInterval(()=>{if(cancelled.has(q.id)){clearInterval(timer);fail(q.id,'operation_aborted')}},5);return;
  }
  if(mode==='no-exit'){send(q.id,{exited:false,verified:false});return}
  for(const target of mode==='co-exit-after-first-stop'?[...open.values()]:[entry])if(!target.exited){target.exited=true;log({op:'owned-exit',pid:target.identity.pid})}send(q.id,{exited:true,verified:true});return;
 }
 if(q.op==='close'){open.delete(q.handle);log({op:'closed',handle:q.handle,pid:entry.identity.pid});send(q.id,{closed:true});return}
 fail(q.id,'unknown_operation');
});
input.on('close',()=>{log({op:'eof',openHandles:open.size});process.exit(open.size===0?0:3)});
