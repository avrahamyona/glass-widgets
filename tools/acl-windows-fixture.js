// GlassWidgets #69 - Windows ACL runtime fixture (self-contained, no repo needed).
// Runs the SAME harden (icacls) + dump (ACL_PS) + evaluator (evalAclDump) as src/lib on a
// scratch directory with a Hebrew/space path. No device private key is read or needed.
// Usage (pick one):
//   node acl-windows-fixture.js
//   PowerShell: $env:ELECTRON_RUN_AS_NODE=1; & "$env:LOCALAPPDATA\Programs\GlassWidgets\GlassWidgets.exe" .\acl-windows-fixture.js
const fs=require('fs'),os=require('os'),path=require('path'),{execFileSync}=require('child_process');
if(process.platform!=='win32'){console.error('This fixture runs on Windows only.');process.exit(2)}
const ACL_PS="$ErrorActionPreference='Stop';$p=$env:GW_ACL_PATH;$acl=Get-Acl -LiteralPath $p;$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$rules=@();foreach($x in $acl.Access){$sid=$null;try{$sid=$x.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=[string]$x.IdentityReference};$rules+=@{sid=$sid;rights=[int64]$x.FileSystemRights;allow=($x.AccessControlType -eq 'Allow');inherited=[bool]$x.IsInherited}};$own=$null;try{$own=([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$own=[string]$acl.Owner};@{me=$me;protected=[bool]$acl.AreAccessRulesProtected;owner=$own;rules=$rules}|ConvertTo-Json -Compress -Depth 4";
// Pure evaluation of a PowerShell Get-Acl JSON dump for owner-only verification.
// Electron-free by design so tests/agent-acl-unit.js can drive it with fixtures on any platform.
// The dump comes from: (Get-Acl -LiteralPath <p>).Access projected to
// {me, rules:[{sid,rights,allow,inherited}]} (see agent.js ACL_PS).
const FULL_CONTROL=2032127; // 0x1F01FF - every right the owner may hold is within this mask
function evalAclDump(dump,meSid){
 if(!dump||typeof dump!=='object')return false;
 if(String(dump.me)!==String(meSid))return false; // the dump itself must resolve the same identity
 if(dump.protected!==true)return false; // DACL protected - inheritance explicitly stripped
 if(String(dump.owner)!==String(meSid))return false; // the file OWNER must be the expected SID
 let rules=dump.rules;
 if(rules&&!Array.isArray(rules))rules=[rules]; // ConvertTo-Json emits a bare object for ONE rule
 if(!Array.isArray(rules)||rules.length!==1)return false; // exactly one ACE, no more
 const r=rules[0];
 if(String(r.sid)!==String(meSid))return false; // exact SID match - never a username substring
 if(r.allow!==true)return false; // Allow only - a Deny or mixed entry fails
 if(r.inherited!==false)return false; // explicitly non-inherited - a MISSING flag never passes
 if(!Number.isInteger(r.rights)||r.rights<0||r.rights>FULL_CONTROL)return false; // bounded integer: a >32-bit value can never smuggle past a bitwise mask
 return true;
}


function currentSid(){
 const out=execFileSync('powershell',['-NoP','-NonI','-ExecutionPolicy','Bypass','-Command','[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],{windowsHide:true,timeout:8000}).toString().trim();
 return /^S-1-5-[0-9-]+$/.test(out)?out:null;
}
function aclDump(p){
 const b64=Buffer.from(ACL_PS,'utf16le').toString('base64');
 const out=execFileSync('powershell',['-NoP','-NonI','-ExecutionPolicy','Bypass','-EncodedCommand',b64],{env:{...process.env,GW_ACL_PATH:p},windowsHide:true,timeout:10000}).toString();
 return JSON.parse(out);
}
function aclHarden(p,isDir){
 const sid=currentSid();if(!sid)throw new Error('no SID');
 execFileSync('icacls',[p,'/inheritance:r','/grant:r','*'+sid+(isDir?':(OI)(CI)(F)':':(R,W)')],{windowsHide:true,timeout:8000});
}
const me=currentSid();
console.log('fixture: node '+process.version+' | os '+os.platform()+' '+os.release()+' | me '+me);
const base=fs.mkdtempSync(path.join(os.tmpdir(),'gw-acl-'));
const results=[];
try{ // finally: the scratch dir is ALWAYS cleaned up, even when a case throws mid-setup
function runCase(name,target,expect,setup){
 if(setup)setup();
 const dump=aclDump(target);
 const got=evalAclDump(dump,dump&&dump.me);
 const pass=got===expect;
 results.push(pass);
 console.log('---CASE '+name+'---');
 console.log('path: '+target);
 console.log('expected: '+expect+' | got: '+got+' | '+(pass?'PASS':'FAIL'));
 console.log('dump: '+JSON.stringify(dump));
}
// A) positive: owner-only hardened dir + file on a Hebrew/space path -> true,true
const dirHe=path.join(base,'בדיקה עם רווח');fs.mkdirSync(dirHe);
const fileHe=path.join(dirHe,'קובץ בדיקה.txt');fs.writeFileSync(fileHe,'dummy - not secret\n');
runCase('A-dir-owner-only-hebrew-space',dirHe,true,()=>aclHarden(dirHe,true));
runCase('A-file-owner-only-hebrew-space',fileHe,true,()=>aclHarden(fileHe,false));
// B) extra Users ACE (well-known SID S-1-5-32-545, locale-independent) -> false
runCase('B-extra-users-ace',fileHe,false,()=>execFileSync('icacls',[fileHe,'/grant','*S-1-5-32-545:(R)'],{windowsHide:true,timeout:8000}));
// C) inherited ACE: parent grants Users (OI)(CI), child inherits -> false
const dirInh=path.join(base,'inherited');fs.mkdirSync(dirInh);
const fileInh=path.join(dirInh,'child.txt');
runCase('C-inherited-ace',fileInh,false,()=>{
 execFileSync('icacls',[dirInh,'/grant','*S-1-5-32-545:(OI)(CI)(R)'],{windowsHide:true,timeout:8000});
 fs.writeFileSync(fileInh,'dummy - not secret\n');
});
const ok=results.every(Boolean);
console.log('FIXTURE: '+(ok?'PASS':'FAIL')+' ('+results.filter(Boolean).length+'/'+results.length+' cases)');
process.exitCode=ok?0:1;
}catch(e){console.error('FIXTURE: ERROR - '+String(e&&e.message||e));process.exitCode=1}
finally{try{fs.rmSync(base,{recursive:true,force:true});console.log('cleanup: scratch removed')}catch(e){console.log('cleanup: FAILED - scratch left at '+base+' ('+e.message+') - delete it manually')}}
