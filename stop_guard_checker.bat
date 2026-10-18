@echo off
setlocal
powershell -NoProfile -Command "$guardProcs=Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^python(w)?\.exe$' -and $_.CommandLine -match 'src\.local_api_server' }; foreach ($item in $guardProcs) { Stop-Process -Id $item.ProcessId -Force -ErrorAction SilentlyContinue }; if ($guardProcs.Count -eq 0) { Write-Output 'No Guard checker was running.' } else { Write-Output 'Local Guard checker stopped.' }"
endlocal
