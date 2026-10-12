// Shared Windows ACL harden+verify helpers - the SINGLE module used by BOTH the Electron
// agent (src/lib/agent.js) and the standalone server (server/index.js). Electron-free.
// Windows ACL helpers (mode bits are a no-op there). Verification is PowerShell Get-Acl with
 // SID-typed JSON output - NOT icacls text (whose first ACE rides the filepath line, whose summary
 // is localized, and whose names are unresolvable-SID ambiguous). The pure evaluator lives in
 // acl-check.js and is fixture-tested.
 const{evalAclDump}=require('./acl-check');
 const{execFileSync}=require('child_process');
 // the dump also carries DACL protection + owner SID; the path travels via ENV (never argv
 // interpolation), the script via -EncodedCommand (UTF-16LE base64) - no shell parsing of either.
 const ACL_PS="$ErrorActionPreference='Stop';$p=$env:GW_ACL_PATH;$acl=Get-Acl -LiteralPath $p;$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$rules=@();foreach($x in $acl.Access){$sid=$null;try{$sid=$x.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=[string]$x.IdentityReference};$rules+=@{sid=$sid;rights=[int64]$x.FileSystemRights;allow=($x.AccessControlType -eq 'Allow');inherited=[bool]$x.IsInherited}};$own=$null;try{$own=([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$own=[string]$acl.Owner};@{me=$me;protected=[bool]$acl.AreAccessRulesProtected;owner=$own;rules=$rules}|ConvertTo-Json -Compress -Depth 4";
 const aclDump=p=>{
  const b64=Buffer.from(ACL_PS,'utf16le').toString('base64');
  const out=execFileSync('powershell',['-NoP','-NonI','-ExecutionPolicy','Bypass','-EncodedCommand',b64],{env:{...process.env,GW_ACL_PATH:p},windowsHide:true,timeout:10000}).toString();
  return JSON.parse(out);
 };
 function currentSid(){
  if(process.platform!=='win32')return null;
  try{const out=execFileSync('powershell',['-NoP','-NonI','-ExecutionPolicy','Bypass','-Command','[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],{windowsHide:true,timeout:8000}).toString().trim();
   return /^S-1-5-[0-9-]+$/.test(out)?out:null}catch{return null}
 }
 function aclOwnerOnly(p){
  if(process.platform!=='win32')return true;
  try{
   const dump=aclDump(p);
   return evalAclDump(dump,dump&&dump.me); // exact-SID, allow-only, non-inherited, rights-bounded, single-ACE, protected DACL, expected owner
  }catch{return false}
 }
 function aclHarden(p,isDir){
  if(process.platform!=='win32')return true;
  const sid=currentSid();if(!sid)return false;
  try{execFileSync('icacls',[p,'/inheritance:r','/grant:r','*'+sid+(isDir?':(OI)(CI)(F)':':(R,W)')],{windowsHide:true,timeout:8000});return aclOwnerOnly(p)}catch{return false}
 }
module.exports={ACL_PS,aclDump,currentSid,aclOwnerOnly,aclHarden};
