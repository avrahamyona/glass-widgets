'use strict';
const {pathToFileURL}=require('node:url'),path=require('node:path');
// Install only in the application main process. Renderers supply no process,
// session, installation, launcher or policy parameters.
function registerServerControlIpc({ipcMain,getManagementWindow,settingsFile,control}={}){
 if(!ipcMain||typeof ipcMain.handle!=='function'||typeof getManagementWindow!=='function'||typeof settingsFile!=='string'||!path.isAbsolute(settingsFile)||!control||['status','start','stop'].some(k=>typeof control[k]!=='function'))throw Error('server_ipc_configuration_required');
 const trustedUrl=pathToFileURL(settingsFile).href,channels=[];
 function permitted(event){
  try{
   const win=getManagementWindow(),contents=win?.webContents;
   return !!win&&!win.isDestroyed()&&!!contents&&!contents.isDestroyed()&&event?.sender===contents&&event.senderFrame===contents.mainFrame&&event.senderFrame?.url===trustedUrl&&contents.getURL()===trustedUrl;
  }catch{return false}
 }
 function safeError(value){return /^[a-z_]{1,80}$/.test(value||'')?value:'server_control_failed'}
 function sanitize(method,result){
  if(!result||typeof result!=='object')return {ok:false,error:'server_control_unverified'};
  if(method==='status'){
   const verified=result.verified===true&&typeof result.running==='boolean';
   return {ok:verified,verified,provisioned:result.provisioned===true,running:verified?result.running:null,desiredIntent:['running','stopped'].includes(result.desiredIntent)?result.desiredIntent:null,blocked:result.blocked===true,inProgress:result.inProgress===true,requiresReconciliation:result.requiresReconciliation===true,...(result.error?{error:safeError(result.error)}:{})};
  }
  const verified=result.ok===true&&result.verified===true;
  return {ok:verified,verified,...(['running','stopped'].includes(result.intent)?{intent:result.intent}:{}),requiresReconciliation:result.requiresReconciliation===true,durableBarrier:result.durableBarrier===true,...(!verified?{error:safeError(result.error)}:{})};
 }
 for(const method of ['status','start','stop']){
  const channel='server:'+method;
  ipcMain.handle(channel,async(event,...args)=>{
   if(!permitted(event))return {ok:false,error:'server_control_sender_rejected'};
   if(args.length!==0)return {ok:false,error:'server_control_parameters_rejected'};
   try{return sanitize(method,await control[method]())}catch{return {ok:false,error:'server_control_failed'}}
  });channels.push(channel);
 }
 return Object.freeze({dispose:()=>{for(const channel of channels)ipcMain.removeHandler(channel)}});
}
module.exports={registerServerControlIpc};
