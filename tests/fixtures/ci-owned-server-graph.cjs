'use strict';
// CI-only graph. No network, application configuration, restart loop or account access.
const cp=require('node:child_process');
if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_REPOSITORY!=='avrahamyona/glass-widgets'||process.env.GITHUB_REF!=='refs/heads/validation/receive-native-20261122'||!process.env.GW_OWNED_FIXTURE_NONCE)throw Error('isolated_windows_ci_only');
const watchdog=setTimeout(()=>process.exit(91),90000);
if(process.argv[2]==='server'){
 setInterval(()=>{},1000);
}else if(process.argv[2]==='supervisor'){
 if(typeof process.send!=='function')throw Error('private_fixture_channel_required');
 const server=cp.spawn(process.execPath,[__filename,'server'],{stdio:'ignore',windowsHide:true,shell:false,env:process.env});
 server.once('error',()=>process.exit(92));
 server.once('spawn',()=>process.send({kind:'owned-graph',nonce:process.env.GW_OWNED_FIXTURE_NONCE,supervisorPid:process.pid,serverPid:server.pid}));
 process.on('message',message=>{
  if(message?.kind!=='cleanup-owned-graph'||message.nonce!==process.env.GW_OWNED_FIXTURE_NONCE)return;
  if(server.exitCode!==null||server.signalCode!==null){clearTimeout(watchdog);process.exit(0);return}
  server.once('exit',()=>{clearTimeout(watchdog);process.exit(0)});
  server.kill(); // The exact child object created above, never a discovered PID.
 });
 process.on('disconnect',()=>{
  // If the harness dies before the reviewed stop begins, clean up this own child.
  if(server.exitCode!==null||server.signalCode!==null){process.exit(0);return}
  server.once('exit',()=>process.exit(0));server.kill();
 });
}else throw Error('explicit_owned_fixture_role_required');
