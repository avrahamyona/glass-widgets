# precheck-tests.ps1 - deterministic adversarial tests for win-enroll-precheck.txt.
# Runs on any pwsh 7+ dev box. The EXACT shipped helper block AND the EXACT shipped C#
# source are extracted from the fixture file itself - never copies. The C# is compiled
# here with Add-Type (P/Invoke declarations compile cross-platform; only Run() execution
# is Windows-only and stays on the Windows acceptance list).
param([string]$Body=(Join-Path $PSScriptRoot 'body.ps1'))
$ErrorActionPreference='Stop'
$script:pass=0; $script:fail=0
function T($name,$cond){ if($cond){ $script:pass++; Write-Output ('PASS '+$name) } else { $script:fail++; Write-Output ('FAIL '+$name) } }
$bodyText=[System.IO.File]::ReadAllText($Body)

# --- extract and load the exact shipped helper block ---
$hs=$bodyText.IndexOf('function ConvertTo-NormalizedVersion')
$hm=$bodyText.IndexOf('# ---------- main flow ----------')
if($hs -lt 0 -or $hm -lt 0 -or $hm -le $hs){ throw 'cannot isolate the helper block from the fixture' }
. ([ScriptBlock]::Create($bodyText.Substring($hs,$hm-$hs)))

# --- extract and COMPILE the exact shipped C# (compile evidence, not runtime evidence) ---
$csMark=$bodyText.IndexOf('# GW-CS-BEGIN')
$csStart=$bodyText.IndexOf("@'",$csMark)+2
$csEnd=$bodyText.IndexOf("'@",$csStart)
if($csMark -lt 0 -or $csStart -lt 2 -or $csEnd -le $csStart){ throw 'cannot isolate the C# block from the fixture' }
$cs=$bodyText.Substring($csStart,$csEnd-$csStart)
$compileOk=$true; $compileErr=''
try{ Add-Type -TypeDefinition $cs -ErrorAction Stop }catch{ $compileOk=$false; $compileErr=$_.Exception.Message }
T 'cs-compiles' $compileOk
if(-not $compileOk){ Write-Output ('compile error: '+$compileErr) }

# --- Quote(): the exact shipped C# running on this box, adversarial argv cases ---
T 'quote-plain'           ([GwBounded]::Quote('C:\x\app.exe',@('abc')) -ceq 'C:\x\app.exe abc')
T 'quote-exe-space'       ([GwBounded]::Quote('C:\a b\app.exe',@('--x','v v')) -ceq '"C:\a b\app.exe" --x "v v"')
T 'quote-empty-arg'       ([GwBounded]::Quote('C:\app.exe',@('')) -ceq 'C:\app.exe ""')
T 'quote-embedded-quote'  ([GwBounded]::Quote('C:\app.exe',@('a"b')) -ceq '"a\"b"'.Insert(0,'C:\app.exe '))
T 'quote-trailing-bs-nospace' ([GwBounded]::Quote('C:\app.exe',@('a\')) -ceq 'C:\app.exe a\')
T 'quote-trailing-bs-quoted' ([GwBounded]::Quote('C:\app.exe',@('a b\')) -ceq 'C:\app.exe "a b\\"')
T 'quote-bs-before-quote' ([GwBounded]::Quote('C:\app.exe',@('a\"b')) -ceq 'C:\app.exe "a\\\"b"')
T 'quote-bs-no-quote'     ([GwBounded]::Quote('C:\app.exe',@('a\b')) -ceq 'C:\app.exe a\b')
T 'quote-tab-arg'         ([GwBounded]::Quote('C:\app.exe',@('a'+[char]9+'b')) -ceq ('C:\app.exe "a'+[char]9+'b"'))
T 'quote-multi-args'      ([GwBounded]::Quote('C:\app.exe',@('a','b c','d')) -ceq 'C:\app.exe a "b c" d')

# --- version gate (PE normalization) ---
T 'ver-pe-4part-padded'   ((Test-VersionGate '0.4.64.0' '0.4.64') -eq '')
T 'ver-exact'             ((Test-VersionGate '0.4.64' '0.4.64') -eq '')
T 'ver-real-4th-part'     ((Test-VersionGate '0.4.64.1' '0.4.64') -ne '')
T 'ver-prerelease-kept'   ((Test-VersionGate '0.4.64-beta.1' '0.4.64') -ne '')
T 'ver-older'             ((Test-VersionGate '0.4.63' '0.4.64') -ne '')
T 'ver-unreadable'        ((Test-VersionGate '' '0.4.64') -ne '')
T 'ver-expected-missing'  ((Test-VersionGate '0.4.64' '') -ne '')
T 'ver-normalize-5part'   ((ConvertTo-NormalizedVersion '1.2.3.0.0') -eq '1.2.3')
T 'ver-expected-normalized-too' ((Test-VersionGate '0.4.64' '0.4.64.0') -eq '')

# --- runtime-evidence parser ---
$NL=[char]10
$now=[DateTimeOffset]::Now.ToUnixTimeMilliseconds()
function MJ($o){ ($o | ConvertTo-Json -Compress) }
$base=[ordered]@{v=1;nonce='n1';isPackaged=$true;exe='C:\x\GlassWidgets.exe';version='0.4.64';ts=$now;userData='C:\Users\u\AppData\Roaming\GlassWidgets'}
function Clone-Base { $h=[ordered]@{}; foreach($k in $base.Keys){ $h[$k]=$base[$k] }; return $h }
function CP($raw,$nonce='n1',$ver='0.4.64',$exe='C:\x\GlassWidgets.exe'){ ConvertTo-RuntimeEvidence -Raw $raw -Nonce $nonce -ExpectedVersion $ver -AppExe $exe -NowMs $now }
T 'json-ok'               ((CP (MJ $base)).ok -eq $true)
$unc=(Clone-Base); $unc.userData='\\server\share\dir'
T 'json-unc-userdata-ok'  ((CP (MJ $unc)).ok -eq $true)
T 'json-empty'            ((CP '').ok -eq $false)
T 'json-whitespace'       ((CP ('  '+$NL+' ')).ok -eq $false)
T 'json-array-scalars'    ((CP '[1,2]').ok -eq $false)
T 'json-array-objects'    ((CP ('['+(MJ $base)+']')).ok -eq $false)
T 'json-two-documents'    ((CP ((MJ $base)+$NL+(MJ $base))).ok -eq $false)
T 'json-trailing-junk'    ((CP ((MJ $base)+$NL+'junk')).ok -eq $false)
T 'json-leading-junk'     ((CP ('junk'+$NL+(MJ $base))).ok -eq $false)
T 'json-scalar-string'    ((CP '"hello"').ok -eq $false)
T 'json-scalar-number'    ((CP '123').ok -eq $false)
T 'json-malformed'        ((CP '{"v":1,').ok -eq $false)
T 'json-wrong-nonce'      ((CP (MJ $base) 'other').ok -eq $false)
$bad=(Clone-Base); $bad.Remove('isPackaged')
T 'json-isPackaged-missing' ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.isPackaged='true'
T 'json-isPackaged-string'  ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.exe='C:\y\other.exe'
T 'json-exe-mismatch'     ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.version='0.4.63'
T 'json-version-mismatch' ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.ts=$now-120000
T 'json-ts-stale-past'    ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.ts=$now+120000
T 'json-ts-stale-future'  ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.ts='123'
T 'json-ts-string'        ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.userData='device\x'
T 'json-userdata-relative' ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.userData=''
T 'json-userdata-empty'   ((CP (MJ $bad)).ok -eq $false)
$bad=(Clone-Base); $bad.v=2
T 'json-schema-v2'        ((CP (MJ $bad)).ok -eq $false)

# --- probe output parser ---
T 'probe-ok'              ((ConvertTo-ProbeResult 'OK 0123456789abcdef').state -eq 'ok' -and (ConvertTo-ProbeResult 'OK 0123456789abcdef').deviceId -eq '0123456789abcdef')
T 'probe-mismatch'        ((ConvertTo-ProbeResult 'MISMATCH').state -eq 'mismatch')
T 'probe-corrupt'         ((ConvertTo-ProbeResult 'CORRUPT').state -eq 'corrupt')
T 'probe-trailing-extra'  ((ConvertTo-ProbeResult 'OK 0123456789abcdef extra').state -eq 'error')
T 'probe-uppercase-hex'   ((ConvertTo-ProbeResult 'OK 0123456789ABCDEF').state -eq 'error')
T 'probe-empty'           ((ConvertTo-ProbeResult '').state -eq 'error')

# --- stage preservation decision ---
function MR($started,$timedOut,$cleaned,$active=0,$code=0,$api=''){ [pscustomobject]@{started=$started;timedOut=$timedOut;treeCleaned=$cleaned;activeAfterExit=$active;exitCode=$code;stdout='';stderr='';apiError=$api} }
T 'closure-empty-ok'      ((Test-ClosureProven @()) -eq $true)
T 'closure-clean-ok'      ((Test-ClosureProven @((MR $true $false $true))) -eq $true)
T 'closure-timeout-clean-ok' ((Test-ClosureProven @((MR $true $true $true))) -eq $true)
T 'closure-unproven-preserve' ((Test-ClosureProven @((MR $true $true $false))) -eq $false)
T 'closure-not-started-ok' ((Test-ClosureProven @((MR $false $false $false -1 $null 'x'))) -eq $true)
T 'closure-one-bad-among-good' ((Test-ClosureProven @((MR $true $false $true),(MR $true $true $false))) -eq $false)

# --- run assessment: every adversarial outcome rejected explicitly ---
T 'assess-clean'          ((Get-RunAssessment (MR $true $false $true 0 0) 'X') -eq '')
T 'assess-api-error'      ((Get-RunAssessment (MR $false $false $false -1 -1 'CreateProcess failed (win32 2)') 'X') -ne '')
T 'assess-not-started'    ((Get-RunAssessment (MR $false $false $true -1 -1 '') 'X') -ne '')
T 'assess-timeout-contained' ((Get-RunAssessment (MR $true $true $true) 'X') -ne '')
T 'assess-timeout-unverified' ((Get-RunAssessment (MR $true $true $false) 'X') -ne '')
T 'assess-nonzero-exit'   ((Get-RunAssessment (MR $true $false $true 0 2) 'X') -ne '')
T 'assess-natural-exit-with-descendant' ((Get-RunAssessment (MR $true $false $true 2 0) 'X') -ne '')

# --- per-child env wrapper (real env on this box) ---
[Environment]::SetEnvironmentVariable('GW_T1','parent','Process')
$seen=''
Invoke-WithChildEnv -EnvRemove @{GW_T1=1} -EnvSet @{GW_T2='child'} -Body { $script:seen=([string][Environment]::GetEnvironmentVariable('GW_T1','Process'))+'|'+([string][Environment]::GetEnvironmentVariable('GW_T2','Process')) }
T 'env-child-view'        ($seen -eq '|child')
T 'env-parent-restored'   (([Environment]::GetEnvironmentVariable('GW_T1','Process')) -eq 'parent')
T 'env-newvar-unset-after' ($null -eq [Environment]::GetEnvironmentVariable('GW_T2','Process'))
$threw=$false
try{ Invoke-WithChildEnv -EnvSet @{GW_T3='x'} -Body { throw 'boom' } }catch{ $threw=$true }
T 'env-restore-on-exception' ($threw -and ($null -eq [Environment]::GetEnvironmentVariable('GW_T3','Process')))

# --- Invoke-BoundedProcess with deterministic Runner mocks ---
$tmpDir=Join-Path ([System.IO.Path]::GetTempPath()) ('gw-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$r1=Invoke-BoundedProcess -ExePath 'C:\x.exe' -OutDir $tmpDir -Runner { param($e,$a,$op,$ep,$t) [System.IO.File]::WriteAllText($op,'CAPTURED'); MR $true $true $true }
T 'bp-timeout-contained'  ($r1.timedOut -and $r1.treeCleaned -and ($r1.stdout -eq 'CAPTURED'))
$r2=Invoke-BoundedProcess -ExePath 'C:\x.exe' -OutDir $tmpDir -Runner { param($e,$a,$op,$ep,$t) MR $true $true $false }
T 'bp-timeout-unverified' ($r2.timedOut -and (-not $r2.treeCleaned))
$r3=Invoke-BoundedProcess -ExePath 'C:\x.exe' -OutDir $tmpDir -Runner { param($e,$a,$op,$ep,$t) MR $false $false $false -1 $null 'CreateJobObject failed (win32 5)' }
T 'bp-api-error-surfaced' ((-not $r3.started) -and ($r3.apiError -like '*CreateJobObject*'))
$r4=Invoke-BoundedProcess -ExePath 'C:\x.exe' -OutDir $tmpDir -Runner { param($e,$a,$op,$ep,$t) [System.IO.File]::WriteAllText($op,('{"v":1}'+$NL+'{"v":2}')); MR $true $false $true 0 0 }
T 'bp-readback-fidelity-multiline' ($r4.stdout -eq ('{"v":1}'+$NL+'{"v":2}'))
$r5=Invoke-BoundedProcess -ExePath 'C:\x.exe' -OutDir $tmpDir -Runner { param($e,$a,$op,$ep,$t) MR $true $false $true 0 2 }
T 'bp-exit-nonzero'       ($r5.exitCode -eq 2)
$r6=Invoke-BoundedProcess -ExePath 'C:\x.exe' -OutDir $tmpDir -Runner { param($e,$a,$op,$ep,$t) MR $true $false $true 3 0 }
T 'bp-descendants-surfaced' ($r6.activeAfterExit -eq 3)
Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

# --- static contract audits on the shipped fixture text ---
foreach($x in @('Add-Type','CREATE_SUSPENDED','AssignProcessToJobObject','JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE','TerminateJobObject','QueryInformationJobObject','STARTF_USESTDHANDLES','STAGING PRESERVED','-ExeSha256')){
  T ('static-has-'+$x) ($bodyText.Contains($x))
}
foreach($x in @('ArgumentList','Get-CimInstance','.GetAwaiter(','RedirectStandardOutput',' -Parallel')){
  T ('static-lacks-'+$x) (-not $bodyText.Contains($x))
}
$runIdx=$bodyText.IndexOf('public static Result Run')
$cpi=$bodyText.IndexOf('CreateProcess(null',$runIdx); $asi=$bodyText.IndexOf('AssignProcessToJobObject(job',$runIdx); $rsi=$bodyText.IndexOf('ResumeThread(thread',$runIdx)
T 'static-suspended-assign-resume-order' ($runIdx -ge 0 -and $cpi -gt $runIdx -and $asi -gt $cpi -and $rsi -gt $asi)
$finIdx=$bodyText.LastIndexOf('}finally{')
$tcp=$bodyText.IndexOf('if(Test-ClosureProven $runs)',$finIdx); $rmi=$bodyText.IndexOf('Remove-Item -LiteralPath $stage',$finIdx); $pres=$bodyText.IndexOf('STAGING PRESERVED',$finIdx)
T 'static-remove-guarded-by-closure' ($finIdx -ge 0 -and $tcp -gt $finIdx -and $rmi -gt $tcp -and $pres -gt $rmi)

Write-Output ('TOTAL pass='+$script:pass+' fail='+$script:fail)
if($script:fail -gt 0){ exit 1 }
