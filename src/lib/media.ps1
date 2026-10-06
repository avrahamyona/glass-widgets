# Persistent helper: prints one JSON line per second describing the current Windows media session,
# and executes commands written to the file given as -CmdFile (play, pause, toggle, next, prev).
param([string]$CmdFile)
$ErrorActionPreference = 'Stop'
function Fail($m){ [Console]::WriteLine((@{err="$m"} | ConvertTo-Json -Compress)); [Console]::Out.Flush() }
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($op, $type) { $t = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); [void]$t.Wait(-1); $t.Result }
[void][Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager,Windows.Media.Control,ContentType=WindowsRuntime]
[void][Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties,Windows.Media.Control,ContentType=WindowsRuntime]
[void][Windows.Storage.Streams.DataReader,Windows.Storage.Streams,ContentType=WindowsRuntime]
[void][Windows.Storage.Streams.IRandomAccessStreamWithContentType,Windows.Storage.Streams,ContentType=WindowsRuntime]
$mgr = Await ([Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager]::RequestAsync()) ([Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager])
} catch { Fail("init: " + $_.Exception.Message); exit 1 }
$lastKey = ''; $art = ''
while ($true) {
 try {
  if ($CmdFile -and (Test-Path $CmdFile)) {
    $cmd = (Get-Content $CmdFile -Raw).Trim(); Remove-Item $CmdFile -Force
    $cs = $mgr.GetCurrentSession()
    if ($cs) {
      switch ($cmd) {
        'toggle' { [void](Await ($cs.TryTogglePlayPauseAsync()) ([bool])) }
        'play'   { [void](Await ($cs.TryPlayAsync()) ([bool])) }
        'pause'  { [void](Await ($cs.TryPauseAsync()) ([bool])) }
        'next'   { [void](Await ($cs.TrySkipNextAsync()) ([bool])) }
        'prev'   { [void](Await ($cs.TrySkipPreviousAsync()) ([bool])) }
      }
    }
  }
  $s = $mgr.GetCurrentSession()
  if (-not $s) { [Console]::WriteLine('{"none":true}') }
  else {
    $p = Await ($s.TryGetMediaPropertiesAsync()) ([Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties])
    $pb = $s.GetPlaybackInfo(); $tl = $s.GetTimelineProperties()
    $key = "$($s.SourceAppUserModelId)|$($p.Title)|$($p.Artist)"
    if ($key -ne $lastKey) {
      $lastKey = $key; $art = ''
      if ($p.Thumbnail) {
        try {
          $st = Await ($p.Thumbnail.OpenReadAsync()) ([Windows.Storage.Streams.IRandomAccessStreamWithContentType])
          $rd = New-Object Windows.Storage.Streams.DataReader($st.GetInputStreamAt(0))
          [void](Await ($rd.LoadAsync([uint32]$st.Size)) ([uint32]))
          $bytes = New-Object byte[] $st.Size; $rd.ReadBytes($bytes)
          $art = 'data:' + $st.ContentType + ';base64,' + [Convert]::ToBase64String($bytes)
        } catch { $art = '' }
      }
    }
    $o = [ordered]@{
      app = $s.SourceAppUserModelId; title = $p.Title; artist = $p.Artist; album = $p.AlbumTitle
      playing = ([int]$pb.PlaybackStatus -eq 4)
      pos = [math]::Round($tl.Position.TotalSeconds, 1); dur = [math]::Round($tl.EndTime.TotalSeconds, 1)
      art = $art
    }
    [Console]::WriteLine(($o | ConvertTo-Json -Compress))
  }
  [Console]::Out.Flush()
  Start-Sleep -Milliseconds 700
 } catch { Fail("loop: " + $_.Exception.Message) }
}
