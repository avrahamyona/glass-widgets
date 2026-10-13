# precheck-tests.ps1 - deterministic mocked tests for win-enroll-precheck.txt helpers.
# Runs on any pwsh 7+ (Linux dev box or Windows). The EXACT shipped helper block is
# extracted from the fixture file itself (between the first helper and the main-flow
# marker) - the main flow is never executed here.
param([string]$Body=(Join-Path $PSScriptRoot 'body.ps1'))
$ErrorActionPreference='Stop'
$script:pass=0; $script:fail=0
function T($name,$cond){ if($cond){ $script:pass++; Write-Output ('PASS '+$name) } else { $script:fail++; Write-Output ('FAIL '+$name) } }
$bodyText=[System.IO.File]::ReadAllText($Body)
$start=$bodyText.IndexOf('function ConvertTo-NormalizedVersion')
$mark=$bodyText.IndexOf('# ---------- main flow ----------')
if($start -lt 0 -or $mark -lt 0 -or $mark -le $start){ throw 'cannot isolate the helper block from the fixture' }
. ([ScriptBlock]::Create($bodyText.Substring($start,$mark-$start)))
$NL=[char]10
$now=[DateTimeOffset]::Now.ToUnixTimeMilliseconds()
function MJ($o){ ($o | ConvertTo-Json -Compress) }
$base=[ordered]@{v=1;nonce='n1';isPackaged=$true;exe='C:\x\GlassWidgets.exe';version='0.4.64';ts=$now;userData='C:\Users\u\AppData\Roaming\GlassWidgets'}
function Clone-Base { $h=[ordered]@{}; foreach($k in $base.Keys){ $h[$k]=$base[$k] }; return $h }
function CP($raw,$nonce='n1',$ver='0.4.64',$exe='C:\x\GlassWidgets.exe'){ ConvertTo-RuntimeEvidence -Raw $raw -Nonce $nonce -ExpectedVersion $ver -AppExe $exe -NowMs $now }

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

# --- runtime-evidence parser: positives ---
T 'json-ok'               ((CP (MJ $base)).ok -eq $true)
$unc=(Clone-Base); $unc.userData='\\server\share\dir'
T 'json-unc-userdata-ok'  ((CP (MJ $unc)).ok -eq $true)

# --- runtime-evidence parser: negatives ---
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

# --- process tree kill (fully mocked, deterministic) ---
$kids=@{100=@(101,102);101=@(103);102=@();103=@()}
$order=@()
$treeOk=Stop-ProcessTreeVerified -RootPid 100 -GetChildren { param($pp) @($kids[[int]$pp]) } -KillPid { param($p2) $script:order+=$p2 } -PidAlive { param($p2) $false }
T 'tree-kill-verified'    ($treeOk -eq $true)
T 'tree-kill-order'       (($order -join ',') -eq '103,101,102,100')
T 'tree-kill-root-last'   ($order[$order.Count-1] -eq 100)
$order=@()
$treeAlive=Stop-ProcessTreeVerified -RootPid 100 -GetChildren { param($pp) @() } -KillPid { param($p2) $script:order+=$p2 } -PidAlive { param($p2) $true }
T 'tree-kill-survivor-fails-verification' ($treeAlive -eq $false)

# --- Invoke-BoundedProcess with mocked processes ---
function New-FakeProc {
  param([int]$Id,[bool]$Exits,[int]$Code,[string]$Out,[string]$Err)
  $st=@{exits=$Exits;code=$Code;out=$Out;err=$Err}
  $so=[PSCustomObject]@{}
  $so | Add-Member ScriptMethod ReadToEndAsync { [System.Threading.Tasks.Task]::FromResult([string]$st.out) }.GetNewClosure() | Out-Null
  $se=[PSCustomObject]@{}
  $se | Add-Member ScriptMethod ReadToEndAsync { [System.Threading.Tasks.Task]::FromResult([string]$st.err) }.GetNewClosure() | Out-Null
  $fp=[PSCustomObject]@{Id=$Id;ExitCode=$Code;StandardOutput=$so;StandardError=$se}
  $fp | Add-Member ScriptMethod WaitForExit { param($ms) return [bool]$st.exits }.GetNewClosure() | Out-Null
  $fp | Add-Member ScriptMethod Kill { }.GetNewClosure() | Out-Null
  return $fp
}
$script:killed=@()
$script:fakeTimeout=New-FakeProc -Id 500 -Exits $false -Code 0 -Out '' -Err ''
$to=Invoke-BoundedProcess -ExePath 'C:\x\GlassWidgets.exe' -Arguments @('a') -TimeoutMs 100 -Launcher { param($psi) $script:fakeTimeout } -GetChildren { param($pp) @() } -KillPid { param($p2) $script:killed+=$p2 } -PidAlive { param($p2) $false }
T 'bp-timeout-flag'       ($to.timedOut -eq $true)
T 'bp-timeout-kill-called' ($script:killed -contains 500)
T 'bp-timeout-tree-cleaned' ($to.treeCleaned -eq $true)
T 'bp-timeout-no-exitcode' ($null -eq $to.exitCode)
$script:killed=@()
$to2=Invoke-BoundedProcess -ExePath 'C:\x\GlassWidgets.exe' -Arguments @('a') -TimeoutMs 100 -Launcher { param($psi) $script:fakeTimeout } -GetChildren { param($pp) @() } -KillPid { param($p2) $script:killed+=$p2 } -PidAlive { param($p2) $true }
T 'bp-timeout-survivor-not-clean' ($to2.timedOut -eq $true -and $to2.treeCleaned -eq $false)
$script:fakeExit2=New-FakeProc -Id 501 -Exits $true -Code 2 -Out 'partial' -Err 'boom'
$ne=Invoke-BoundedProcess -ExePath 'C:\x\GlassWidgets.exe' -Arguments @('a') -TimeoutMs 100 -Launcher { param($psi) $script:fakeExit2 }
T 'bp-natural-nonzero-exit' ($ne.timedOut -eq $false -and $ne.exitCode -eq 2)
$script:fakeOk=New-FakeProc -Id 502 -Exits $true -Code 0 -Out 'HELLO-STDOUT' -Err 'E'
$ok=Invoke-BoundedProcess -ExePath 'C:\x\GlassWidgets.exe' -Arguments @('a') -TimeoutMs 5000 -Launcher { param($psi) $script:fakeOk }
T 'bp-natural-ok'         ($ok.timedOut -eq $false -and $ok.exitCode -eq 0 -and $ok.stdout -eq 'HELLO-STDOUT' -and $ok.stderr -eq 'E')

# --- real per-child environment contract (real /bin/sh child on this dev box) ---
$env:ELECTRON_RUN_AS_NODE='1'
$scrub=Invoke-BoundedProcess -ExePath '/bin/sh' -Arguments @('-c','printf %s "${ELECTRON_RUN_AS_NODE:-unset}"') -EnvRemove @{ELECTRON_RUN_AS_NODE=1} -TimeoutMs 5000
T 'env-scrub-real'        ($scrub.exitCode -eq 0 -and $scrub.stdout -eq 'unset')
$setc=Invoke-BoundedProcess -ExePath '/bin/sh' -Arguments @('-c','printf %s "$ELECTRON_RUN_AS_NODE"') -EnvSet @{ELECTRON_RUN_AS_NODE='1'} -TimeoutMs 5000
T 'env-set-child-real'    ($setc.exitCode -eq 0 -and $setc.stdout -eq '1')
T 'env-parent-untouched'  ($env:ELECTRON_RUN_AS_NODE -eq '1')
Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue

# --- real bounded timeout against a real sleeping process (no mock) ---
$rt=Invoke-BoundedProcess -ExePath '/bin/sh' -Arguments @('-c','sleep 30') -TimeoutMs 800 -GetChildren { param($pp) @() } -KillPid { param($p2) try{ Stop-Process -Id $p2 -Force -ErrorAction Stop }catch{} } -PidAlive { param($p2) try{ $null=Get-Process -Id $p2 -ErrorAction Stop; $true }catch{ $false } }
T 'bp-real-timeout'       ($rt.timedOut -eq $true -and $rt.treeCleaned -eq $true)

Write-Output ('TOTAL pass='+$script:pass+' fail='+$script:fail)
if($script:fail -gt 0){ exit 1 }
