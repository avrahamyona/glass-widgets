# Prints one line per Apple (0x004C) BLE advertisement: "AP <hex> <rssi>"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[void][Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher,Windows.Devices.Bluetooth,ContentType=WindowsRuntime]
[void][Windows.Storage.Streams.DataReader,Windows.Storage.Streams,ContentType=WindowsRuntime]
$w = New-Object Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher
$w.ScanningMode = 'Active'
Register-ObjectEvent -InputObject $w -EventName Received -Action {
  $a = $Event.SourceEventArgs
  foreach ($m in $a.Advertisement.ManufacturerData) {
    if ($m.CompanyId -eq 76) {
      $r = [Windows.Storage.Streams.DataReader]::FromBuffer($m.Data)
      $b = New-Object byte[] $m.Data.Length
      $r.ReadBytes($b)
      [Console]::WriteLine('AP ' + ([BitConverter]::ToString($b) -replace '-','') + ' ' + $a.RawSignalStrengthInDBm)
    }
  }
} | Out-Null
$w.Start()
while ($true) { Start-Sleep -Seconds 1 }
