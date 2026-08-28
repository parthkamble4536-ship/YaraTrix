# PowerShell script accessing credentials
Get-StoredCredential | Select-Object *

# Accessing Microsoft Credentials path
$path = "$env:LOCALAPPDATA\Microsoft\Credentials"
$data = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, 'CurrentUser')

cmdkey /list
vaultcmd /list
