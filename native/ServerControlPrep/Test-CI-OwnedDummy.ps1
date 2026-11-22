# HOSTED WINDOWS CI ONLY. Never run on an existing user desktop.
# Targets only a new child created here. No PID argument or existing-process selection.
$ErrorActionPreference='Stop'
$library=Join-Path $PSScriptRoot 'VerifiedProcessHandle.cs'
$expectedSourceHash='acc1783f6d54cdb4385918fdb9faa93252e6298460525b925a12bcd33e0588f0'
if((Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSourceHash){throw 'reviewed_library_hash_required'}
Add-Type -Path $library -ErrorAction Stop
$nodeLines=@(& node -p 'process.execPath')
if($LASTEXITCODE -ne 0 -or $nodeLines.Count -ne 1){throw 'node_discovery_failed'}
$node=([string]$nodeLines[0]).Trim()
if(-not [IO.Path]::IsPathRooted($node) -or -not [IO.File]::Exists($node)){throw 'existing_node_required'}
$current=[Security.Principal.WindowsIdentity]::GetCurrent()
$owner=$current.User.Value
$logons=@($current.Groups|ForEach-Object{$_.Value}|Where-Object{$_ -match '^S-1-5-5-\d+-\d+$'})
if($logons.Count -ne 1){throw 'single_current_logon_sid_required'}
$p=New-Object Diagnostics.Process
$p.StartInfo=New-Object Diagnostics.ProcessStartInfo($node,'-e "setInterval(()=>{},1000)"')
$p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
$started=$false;$exitVerified=$false;$observe=$null;$stop=$null
try{
 if(-not $p.Start()){throw 'new_dummy_start_failed'};$started=$true
 $pidValue=[uint32]$p.Id;$ticks=$p.StartTime.ToUniversalTime().ToFileTimeUtc()
 $identity=New-Object GlassWidgets.ServerControlPrep.ExpectedProcessIdentity($pidValue,$ticks,$node,$owner,$logons[0])
 $wrong=New-Object GlassWidgets.ServerControlPrep.ExpectedProcessIdentity($pidValue,($ticks+1),$node,$owner,$logons[0])
 $mismatchRefused=$false
 try{$bad=[GlassWidgets.ServerControlPrep.VerifiedProcessHandle]::OpenForObservation($wrong);$bad.Dispose();throw 'mismatched_identity_was_accepted'}catch{if($_.Exception.GetBaseException().Message -ne 'native_process_identity_changed'){throw};$mismatchRefused=$true}
 $observe=[GlassWidgets.ServerControlPrep.VerifiedProcessHandle]::OpenForObservation($identity)
 $observationRefused=$false
 try{$observe.RequestTermination([Threading.CancellationToken]::None);throw 'observation_stop_was_accepted'}catch{if($_.Exception.GetBaseException().Message -ne 'observation_handle_cannot_stop'){throw};$observationRefused=$true}
 if($observe.Inspect([Threading.CancellationToken]::None).Exited){throw 'dummy_exited_before_stop_test'}
 $stop=[GlassWidgets.ServerControlPrep.VerifiedProcessHandle]::OpenForStop($identity)
 $cancel=New-Object Threading.CancellationTokenSource;$cancel.Cancel();$cancelRefused=$false
 try{$stop.RequestTermination($cancel.Token);throw 'cancelled_stop_was_accepted'}catch{if($_.Exception.GetBaseException() -isnot [OperationCanceledException]){throw};$cancelRefused=$true}finally{$cancel.Dispose()}
 if($stop.Inspect([Threading.CancellationToken]::None).Exited){throw 'cancelled_stop_killed_dummy'}
 $stop.RequestTermination([Threading.CancellationToken]::None)
 if(-not $stop.WaitForExit(5000,[Threading.CancellationToken]::None)){throw 'dummy_exit_unverified'}
 $exitVerified=$true
 if(-not $observe.Inspect([Threading.CancellationToken]::None).Exited){throw 'observation_exit_unverified'}
 $stop.Dispose();$stop=$null;$observe.Dispose();$observe=$null
 @{compiled=$true;identityMismatchRefused=$mismatchRefused;observationStopRefused=$observationRefused;cancelledStopRefused=$cancelRefused;ownedDummyExited=$true;handlesDisposed=$true;realServerTouched=$false}|ConvertTo-Json -Compress
}finally{
 $cleanupError=$null
 try{if($started -and -not $exitVerified){if(-not $p.HasExited){$p.Kill();if(-not $p.WaitForExit(5000)){throw 'owned_dummy_cleanup_unverified'}}}}catch{$cleanupError=$_}
 foreach($h in @($stop,$observe)){try{if($null -ne $h){$h.Dispose()}}catch{$cleanupError=$_}}
 try{$p.Dispose()}catch{$cleanupError=$_};try{$current.Dispose()}catch{$cleanupError=$_}
 if($null -ne $cleanupError){throw $cleanupError}
}
