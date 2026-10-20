Get-Process stopRKN -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800
Copy-Item -Force "C:\Qt\myIPproxy\build\release\stopRKN.exe" "C:\Program Files\stopRKN\stopRKN.exe"
Start-Process "C:\Program Files\stopRKN\stopRKN.exe"
