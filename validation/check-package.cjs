'use strict';
// Inspects the transient build only. No install, no launch, no publication, no artifact upload.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const asar=require('@electron/asar'),manifest=require('./source-hashes.json');
const archive='dist/win-unpacked/resources/app.asar';assert(fs.existsSync(archive),'packaged_archive_required');
for(const file of ['src/main.js','src/widgets/chat/index.html','src/lib/chat-transport.js']){
 const actual=crypto.createHash('sha256').update(asar.extractFile(archive,file)).digest('hex');assert.equal(actual,manifest[file],'packaged_candidate_hash:'+file);
}
const nativeExcluded=asar.listPackage(archive).every(p=>!p.includes('ServerControlPrep'));assert(nativeExcluded,'native_library_is_not_integrated_in_this_candidate');
const installers=fs.readdirSync('dist').filter(p=>p.endsWith('.exe'));assert.equal(installers.length,1,'one_test_installer_required');
const file=path.join('dist',installers[0]),buf=fs.readFileSync(file);assert(buf.length>1000000);assert.equal(buf.subarray(0,2).toString(),'MZ');
console.log(JSON.stringify({packagedCandidateHashesMatch:true,nativeControllerIntegrated:false,installerBuilt:true,installerBytes:buf.length,installerSha256:crypto.createHash('sha256').update(buf).digest('hex'),installed:false,published:false,downloadableArtifactRetained:false}));
