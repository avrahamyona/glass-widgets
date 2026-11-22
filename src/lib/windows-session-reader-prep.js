'use strict';
const cp=require('child_process'),path=require('path');
function createWindowsSessionReader({execFile=cp.execFile,platform=process.platform,systemRoot=process.env.SystemRoot}={}){
 const call=(exe,args)=>new Promise((resolve,reject)=>execFile(exe,args,{windowsHide:true,timeout:5000,maxBuffer:8192,encoding:'utf8',shell:false},(e,out)=>e?reject(Error('session_query_failed')):resolve(String(out))));
 return async()=>{
  if(platform!=='win32'||typeof systemRoot!=='string'||!path.win32.isAbsolute(systemRoot))throw Error('windows_session_unavailable');
  const base=path.win32.join(systemRoot,'System32');
  const out=await call(path.win32.join(base,'whoami.exe'),['/logonid']);
  const ids=out.match(/S-1-5-5-\d+-\d+/g)||[];if(ids.length!==1)throw Error('logon_id_unverified');
  // Include boot identity because numeric logon IDs are only locally unique.
  const ps=path.win32.join(base,'WindowsPowerShell','v1.0','powershell.exe');
  const boot=JSON.parse(await call(ps,['-NoProfile','-NonInteractive','-Command',"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') | ConvertTo-Json -Compress"]));
  if(typeof boot!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/.test(boot)||!Number.isFinite(Date.parse(boot)))throw Error('boot_id_unverified');
  return {sessionId:ids[0]+':'+Date.parse(boot),source:'windows-logonid-and-boot',readOnly:true};
 };
}
module.exports={createWindowsSessionReader};
