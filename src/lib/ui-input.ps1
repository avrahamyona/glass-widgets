param([int]$X=0,[int]$Y=0,[string]$Action='click')
$ErrorActionPreference='Stop'
$sig='[DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y);[DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint d,System.UIntPtr e);'
$t=Add-Type -MemberDefinition $sig -Name UI -Namespace GW -PassThru
[void]$t::SetCursorPos($X,$Y)
Start-Sleep -Milliseconds 50
$L=0x02;$LU=0x04;$R=0x08;$RU=0x10
switch($Action){
 'move'{}
 'rclick'{$t::mouse_event($R,0,0,0,[System.UIntPtr]::Zero);$t::mouse_event($RU,0,0,0,[System.UIntPtr]::Zero)}
 'dblclick'{1..2|%{$t::mouse_event($L,0,0,0,[System.UIntPtr]::Zero);$t::mouse_event($LU,0,0,0,[System.UIntPtr]::Zero);Start-Sleep -Milliseconds 80}}
 default{$t::mouse_event($L,0,0,0,[System.UIntPtr]::Zero);$t::mouse_event($LU,0,0,0,[System.UIntPtr]::Zero)}
}
Write-Output "ok $Action $X $Y"
