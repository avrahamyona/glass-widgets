'use strict';
// Policy state only, no server/process/startup actions. Directory ACL verification is mandatory.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {plan,POLICY}=require('./server-policy-prep');
function createPolicyStore({dir,verifyPrivateDirectory,fsImpl=fs}){
 if(typeof verifyPrivateDirectory!=='function')throw Error('private_directory_verifier_required');
 const file=path.join(dir,'server-intent-v1.json'),lock=path.join(dir,'server-intent-v1.lock');
 function check(){if(verifyPrivateDirectory(dir)!==true)throw Error('private_directory_unverified');const st=fsImpl.lstatSync(dir);if(!st.isDirectory()||st.isSymbolicLink())throw Error('invalid_directory')}
 function locked(fn){check();let fd;try{fd=fsImpl.openSync(lock,'wx',0o600)}catch(e){if(e.code==='EEXIST')throw Error('policy_busy');throw e}
  try{return fn()}finally{fsImpl.closeSync(fd);fsImpl.unlinkSync(lock)}
 }
 function read(){check();const st=fsImpl.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>4096)throw Error('invalid_state_file');return JSON.parse(fsImpl.readFileSync(file,'utf8'))}
 function write(next){const tmp=file+'.'+crypto.randomUUID()+'.tmp';let fd;
  try{fd=fsImpl.openSync(tmp,'wx',0o600);fsImpl.writeFileSync(fd,JSON.stringify(next)+'\n');fsImpl.fsyncSync(fd);fsImpl.closeSync(fd);fd=undefined;fsImpl.renameSync(tmp,file)}
  finally{if(fd!==undefined)fsImpl.closeSync(fd);try{fsImpl.unlinkSync(tmp)}catch(e){if(e.code!=='ENOENT')throw e}}
 }
 return {
  // Initial installation itself requires a separate approval and known session. Never auto-initialize missing state.
  initialize(state,{installationApproved=false}={}){return locked(()=>{
   if(!installationApproved||!state||state.policy!==POLICY||!plan({event:'app-open',currentSessionId:state.sessionId,persisted:state}).ok)throw Error('reviewed_initialization_required');
   try{fsImpl.lstatSync(file);throw Error('state_exists')}catch(e){if(e.code!=='ENOENT')throw e}
   write(state);return {initialized:true,appliedToServer:false};
  })},
  transition({event,currentSessionId,expectedRevision}){return locked(()=>{
   const old=read();if(old.revision!==expectedRevision)throw Error('state_revision_conflict');
   const result=plan({event,currentSessionId,persisted:old});if(!result.ok)return result;
   write(result.next);return {...result,persisted:true,actionExecuted:false};
  })},
  read
 };
}
module.exports={createPolicyStore};
