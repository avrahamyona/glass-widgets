'use strict';
// A persisted action barrier, not a PID lock. A crashed or uncertain action
// cannot be silently replayed by a new application process. No stale-lock deletion.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const EVENTS=new Set(['manual-start','manual-stop','app-open','recover','windows-logon']);
function createOperationJournal({dir,verifyPrivateDirectory}={}){
 if(typeof dir!=='string'||typeof verifyPrivateDirectory!=='function')throw Error('private_operation_directory_required');
 const file=path.join(dir,'server-operation-v1.json');
 function check(){if(verifyPrivateDirectory(dir)!==true)throw Error('private_directory_unverified');const st=fs.lstatSync(dir);if(!st.isDirectory()||st.isSymbolicLink())throw Error('invalid_operation_directory')}
 function load(){
  check();let fd;
  try{
   const before=fs.lstatSync(file);if(!before.isFile()||before.isSymbolicLink())return {kind:'unverified'};
   fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));const st=fs.fstatSync(fd);
   if(st.ino!==before.ino||st.dev!==before.dev)return {kind:'unverified'};
   if(!st.isFile()||st.nlink!==1||st.size<2||st.size>2048)return {kind:'unverified'};
   const record=JSON.parse(fs.readFileSync(fd,'utf8'));
   if(record.version!==1||!/^[a-f0-9-]{36}$/.test(record.nonce||'')||!/^[a-f0-9-]{36}$/.test(record.controllerId||'')||!EVENTS.has(record.event)||typeof record.installationId!=='string'||record.installationId.length>160||typeof record.persistedSessionId!=='string'||record.persistedSessionId.length>160)return {kind:'unverified'};
   return {kind:'pending',record};
  }catch(error){if(error.code==='ENOENT')return {kind:'none'};return {kind:'unverified'}}
  finally{if(fd!==undefined)fs.closeSync(fd)}
 }
 function begin({controllerId,event,installationId,persistedSessionId}){
  check();if(!EVENTS.has(event)||!/^[a-f0-9-]{36}$/.test(controllerId||'')||typeof installationId!=='string'||!installationId||installationId.length>160||typeof persistedSessionId!=='string'||!persistedSessionId||persistedSessionId.length>160)throw Error('operation_context_required');
  const record={version:1,nonce:crypto.randomUUID(),controllerId,event,installationId,persistedSessionId};let fd;
  try{fd=fs.openSync(file,'wx',0o600)}catch(error){if(error.code==='EEXIST')throw Error('prior_operation_requires_review');throw error}
  // A partial file remains a barrier after a write failure or crash.
  try{fs.writeFileSync(fd,JSON.stringify(record)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  return Object.freeze(record);
 }
 function complete(record){
  check();const current=load();
  if(current.kind!=='pending'||current.record.nonce!==record?.nonce||current.record.controllerId!==record.controllerId||current.record.installationId!==record.installationId)throw Error('operation_token_changed');
  fs.unlinkSync(file);
 }
 return Object.freeze({load,begin,complete});
}
module.exports={createOperationJournal};
