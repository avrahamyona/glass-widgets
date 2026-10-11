param([int]$X=0,[int]$Y=0,[string]$Action='click')
$ErrorActionPreference='Stop'
$sig='[DllImport("shcore.dll")]public static extern int SetProcessDpiAwareness(int v);[DllImport("shcore.dll")]public static extern int GetProcessDpiAwareness(System.IntPtr h,out int v);[DllImport("user32.dll")]public static extern bool SetCursorPos(int X,int Y);[DllImport("user32.dll")]public static extern void mouse_event(uint f,uint dx,uint dy,uint d,UIntPtr e);'
$t=Add-Type -MemberDefinition $sig -Name UI -Namespace GW -PassThru
$hr=$t::SetProcessDpiAwareness(2) # per-monitor DPI aware: SetCursorPos below takes PHYSICAL pixels
if($hr -ne 0 -and $hr -ne -2147024891){Write-Error "SetProcessDpiAwareness failed hr=$hr";exit 1} # E_ACCESSDENIED = context already set by the manifest
$aw=-1;$hr2=$t::GetProcessDpiAwareness([Diagnostics.Process]::GetCurrentProcess().Handle,[ref]$aw)
if($hr2 -ne 0){Write-Error "GetProcessDpiAwareness failed hr=$hr2";exit 1}
if($aw -ne 2){Write-Error "DPI awareness is $aw, need per-monitor (2) for the physical contract";exit 1} # fail closed: system-aware(1)/unaware(0) cannot prove mixed-DPI physical mapping
if(-not $t::SetCursorPos($X,$Y)){Write-Error "SetCursorPos refused ($X,$Y)";exit 1}
Start-Sleep -Milliseconds 50
Add-Type -AN System.Windows.Forms
$pp=[Windows.Forms.Cursor]::Position # observed position, same physical space once DPI-aware
if([Math]::Abs($pp.X-$X)-gt 3 -or [Math]::Abs($pp.Y-$Y)-gt 3){Write-Error "cursor at $($pp.X),$($pp.Y) not $X,$Y";exit 1}
$L=0x02;$LU=0x04;$R=0x08;$RU=0x10
switch($Action){
 'move'{}
 'rclick'{$t::mouse_event($R,0,0,0,[UIntPtr]::Zero);$t::mouse_event($RU,0,0,0,[UIntPtr]::Zero)}
 'dblclick'{1..2|%{$t::mouse_event($L,0,0,0,[UIntPtr]::Zero);$t::mouse_event($LU,0,0,0,[UIntPtr]::Zero);Start-Sleep -Milliseconds 80}}
 default{$t::mouse_event($L,0,0,0,[UIntPtr]::Zero);$t::mouse_event($LU,0,0,0,[UIntPtr]::Zero)}
}
"injected $Action $X $Y"
