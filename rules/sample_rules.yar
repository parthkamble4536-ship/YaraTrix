rule Suspicious_PowerShell_EncodedCommand {
    meta:
        mitre_technique = "T1059.001"
        mitre_tactic    = "execution"
        severity        = "high"
        description     = "Detects PowerShell execution with encoded command argument"
        author          = "YaraTrix"
        reference       = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-ec " nocase

    condition:
        any of them
}


rule LSASS_Memory_Access {
    meta:
        mitre_technique = "T1003.001"
        mitre_tactic    = "credential-access"
        severity        = "critical"
        description     = "Detects LSASS memory dumping via common tools"
        author          = "YaraTrix"
        reference       = "https://attack.mitre.org/techniques/T1003/001/"

    strings:
        $tool1 = "sekurlsa::logonpasswords" nocase
        $tool2 = "procdump" nocase
        $tool3 = "lsass.exe" nocase
        $tool4 = "MiniDumpWriteDump" nocase

    condition:
        any of them
}


rule Persistence_Registry_Run_Key {
    meta:
        mitre_technique = "T1547.001"
        mitre_tactic    = "persistence"
        severity        = "medium"
        description     = "Detects persistence via registry Run keys"
        author          = "YaraTrix"
        reference       = "https://attack.mitre.org/techniques/T1547/001/"

    strings:
        $run1  = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2  = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run3  = "CurrentVersion\\Run" nocase

    condition:
        any of them
}


rule Defense_Evasion_Obfuscated_Script {
    meta:
        mitre_technique = "T1027"
        mitre_tactic    = "defense-evasion"
        severity        = "medium"
        description     = "Detects obfuscated scripts via base64 or character substitution"
        author          = "YaraTrix"
        reference       = "https://attack.mitre.org/techniques/T1027/"

    strings:
        $b64_ps  = "JAB" ascii      // base64 of "$"
        $b64_iex = "SQBFAFYA" ascii // base64 of IEX
        $concat  = "'+'" ascii

    condition:
        2 of them
}


rule Discovery_System_Info {
    meta:
        mitre_technique = "T1082"
        mitre_tactic    = "discovery"
        severity        = "low"
        description     = "Detects system information gathering"
        author          = "YaraTrix"
        reference       = "https://attack.mitre.org/techniques/T1082/"

    strings:
        $cmd1 = "systeminfo" nocase
        $cmd2 = "Get-ComputerInfo" nocase
        $cmd3 = "wmic os get" nocase

    condition:
        any of them
}
