/*
    YaraTrix Credential Access Rules
    Tactic: Credential Access (TA0006)

    Covers:
      - LSASS memory access patterns (T1003.001)
      - Mimikatz-style strings and indicators (T1003.001)
      - SAM database dumping (T1003.002)
      - Credential access via Windows Vault (T1555.004)
*/

rule LSASS_Memory_Access
{
    meta:
        mitre_technique  = "T1003.001"
        mitre_tactic     = "credential-access"
        severity         = "critical"
        description      = "Detects attempts to access LSASS process memory for credential dumping via OpenProcess/MiniDumpWriteDump API combinations or direct process handle operations targeting lsass.exe."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // LSASS process name references
        $lsass1 = "lsass.exe" nocase wide ascii
        $lsass2 = "lsass" nocase wide ascii

        // Memory dump APIs
        $dump1 = "MiniDumpWriteDump" nocase wide ascii
        $dump2 = "OpenProcess" nocase wide ascii
        $dump3 = "ReadProcessMemory" nocase wide ascii
        $dump4 = "NtReadVirtualMemory" nocase wide ascii

        // Common dump file names
        $file1 = "lsass.dmp" nocase wide ascii
        $file2 = "lsass.zip" nocase wide ascii
        $file3 = "debug.dmp" nocase wide ascii

        // Elevated access rights flags (hex values commonly seen)
        $rights1 = "0x1F0FFF" wide ascii  // PROCESS_ALL_ACCESS
        $rights2 = "0x0410" wide ascii    // PROCESS_VM_READ | PROCESS_QUERY_INFO

    condition:
        any of ($lsass*) and
        (
            any of ($dump*) or
            any of ($file*) or
            any of ($rights*)
        )
}


rule Mimikatz_Indicators
{
    meta:
        mitre_technique  = "T1003.001"
        mitre_tactic     = "credential-access"
        severity         = "critical"
        description      = "Detects Mimikatz credential dumping tool signatures including its hardcoded strings, internal module names, and output patterns unique to the tool."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Mimikatz unique strings
        $mimikatz1  = "mimikatz" nocase wide ascii
        $mimikatz2  = "Benjamin DELPY" wide ascii
        $mimikatz3  = "gentilkiwi" nocase wide ascii
        $mimikatz4  = "mimilib" nocase wide ascii

        // Module names unique to Mimikatz
        $module1    = "sekurlsa::" wide ascii
        $module2    = "kerberos::" wide ascii
        $module3    = "lsadump::" wide ascii
        $module4    = "crypto::" wide ascii
        $module5    = "vault::" wide ascii

        // Command strings
        $cmd1       = "privilege::debug" nocase wide ascii
        $cmd2       = "sekurlsa::logonpasswords" nocase wide ascii
        $cmd3       = "sekurlsa::wdigest" nocase wide ascii
        $cmd4       = "lsadump::sam" nocase wide ascii
        $cmd5       = "lsadump::dcsync" nocase wide ascii
        $cmd6       = "lsadump::lsa" nocase wide ascii

        // Output patterns
        $out1       = "NTLM     :" wide ascii
        $out2       = "Password :" wide ascii
        $out3       = "* Username :" wide ascii

    condition:
        2 of ($mimikatz*) or
        2 of ($module*) or
        2 of ($cmd*) or
        (any of ($out*) and any of ($module*))
}


rule SAM_Database_Dump
{
    meta:
        mitre_technique  = "T1003.002"
        mitre_tactic     = "credential-access"
        severity         = "critical"
        description      = "Detects attempts to access or dump the SAM (Security Account Manager) database, which contains local account password hashes. Includes reg save, VSS shadow copy access, and direct SAM path references."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // SAM file references
        $sam1 = "\\SAM" wide ascii
        $sam2 = "\\system32\\config\\SAM" nocase wide ascii
        $sam3 = "\\windows\\system32\\config\\sam" nocase wide ascii

        // Registry save for SAM
        $reg_save1  = "reg save HKLM\\SAM" nocase wide ascii
        $reg_save2  = "reg save hklm\\system" nocase wide ascii
        $reg_save3  = "reg save hklm\\security" nocase wide ascii

        // Shadow copy / VSS access to bypass file lock
        $vss1 = "HarddiskVolumeShadowCopy" nocase wide ascii
        $vss2 = "vssadmin" nocase wide ascii
        $vss3 = "GLOBALROOT\\Device" nocase wide ascii

    condition:
        any of ($sam*) or
        any of ($reg_save*) or
        (any of ($vss*) and $sam1)
}


rule Credential_Vault_Access
{
    meta:
        mitre_technique  = "T1555.004"
        mitre_tactic     = "credential-access"
        severity         = "high"
        description      = "Detects access to Windows Credential Manager / Vault, which stores saved network credentials, browser passwords, and RDP session credentials."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Credential Manager APIs
        $api1 = "CredEnumerate" nocase wide ascii
        $api2 = "CredRead" nocase wide ascii
        $api3 = "CryptUnprotectData" nocase wide ascii
        $api4 = "VaultOpenVault" nocase wide ascii
        $api5 = "VaultEnumerateItems" nocase wide ascii

        // cmdkey and vaultcmd tools
        $tool1 = "cmdkey" nocase wide ascii
        $tool2 = "vaultcmd" nocase wide ascii

        // Known vault paths
        $path1 = "\\Credentials\\" nocase wide ascii
        $path2 = "\\Microsoft\\Credentials" nocase wide ascii
        $path3 = "\\AppData\\Local\\Microsoft\\Credentials" nocase wide ascii

        // PowerShell credential access
        $ps1 = "Get-StoredCredential" nocase wide ascii
        $ps2 = "[System.Security.Cryptography.ProtectedData]" nocase wide ascii

    condition:
        any of ($api*) or
        (any of ($tool*) and any of ($path*)) or
        any of ($ps*)
}
