'use strict';
const assert=require('node:assert/strict');
const {planOwnedChain,revalidateStep,createdAfter}=require('../src/lib/live-chain-plan-prep');
const {planWithAuxiliaries}=require('../src/lib/auxiliary-chain-plan-prep');
const common={createdAt:'2026-11-21T17:07:19.6976620Z',exe:'C:\\Fixture\\owned.exe',ownerSid:'fixture-owner',sessionId:'fixture-session',commandHash:'a'.repeat(64),logonSid:'S-1-5-5-10-20'};
function graph(){const reviewed=[{...common,pid:10,parentPid:1,role:'supervisor',nativeCreatedFileTimeUtc:'134397544396976620'},{...common,pid:20,parentPid:10,role:'server',nativeCreatedFileTimeUtc:'134397544396976621'}];return {reviewed,processes:reviewed.map(p=>({...p})),ownerSid:common.ownerSid,sessionId:common.sessionId}}
let n=0;const test=(name,fn)=>{fn();n++;console.log('ok '+name)};
test('a parent one native tick later is rejected despite equal displayed milliseconds',()=>{const g=graph();g.reviewed[0].nativeCreatedFileTimeUtc='134397544396976622';g.processes[0].nativeCreatedFileTimeUtc=g.reviewed[0].nativeCreatedFileTimeUtc;assert.equal(planOwnedChain(g).error,'parent_pid_reused')});
test('native creation ticks survive planning and are revalidated exactly',()=>{const g=graph(),plan=planOwnedChain(g);assert(plan.ok);assert.equal(plan.steps[1].identity.nativeCreatedFileTimeUtc,'134397544396976621');assert(!revalidateStep(plan.steps[1],{...g.processes[1],nativeCreatedFileTimeUtc:'134397544396976622'}))});
test('auxiliary parent age uses the same native precision',()=>{const g=graph(),aux={...common,pid:30,parentPid:10,role:'observe-only',reason:'fixture helper',nativeCreatedFileTimeUtc:'134397544396976619'};g.processes.push({...aux});assert.equal(planWithAuxiliaries({...g,auxiliaries:[aux]}).error,'auxiliary_parent_reused')});
test('legacy date-only planning remains non-native and does not synthesize ticks',()=>{assert(createdAfter({createdAt:'2026-11-21T17:07:19.698Z'},{createdAt:'2026-11-21T17:07:19.697Z'}));const g=graph();for(const p of [...g.reviewed,...g.processes])delete p.nativeCreatedFileTimeUtc;assert.equal(planOwnedChain(g).steps[0].identity.nativeCreatedFileTimeUtc,undefined)});
console.log(JSON.stringify({checks:n,scope:'pure graph precision, no OS actions'}));
