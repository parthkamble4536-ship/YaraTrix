/*
    YaraTrix Fileless Malware & Living off the Land (LOLBins) Rules
    Tactic: Defense Evasion (TA0005) / Execution (TA0002)
*/

rule LOLBin_Certutil_Download {
    meta:
        mitre_technique = "T1105"
        mitre_tactic    = "command-and-control"
        severity        = "high"
        description     = "Detects malicious use of certutil.exe to download files or decode base64 payloads"
        author          = "YaraTrix Enterprise"

    strings:
        $cu1 = "certutil" nocase ascii wide
        
        $arg1 = "-urlcache" nocase ascii wide
        $arg2 = "-split" nocase ascii wide
        $arg3 = "-f" nocase ascii wide
        $arg4 = "-decode" nocase ascii wide
        
        $http = "http" nocase ascii wide
        
    condition:
        $cu1 and (($arg1 and $arg2 and $arg3 and $http) or $arg4)
}

rule LOLBin_Bitsadmin_Transfer {
    meta:
        mitre_technique = "T1197"
        mitre_tactic    = "defense-evasion"
        severity        = "medium"
        description     = "Detects abuse of BITSAdmin for background file transfers"
        author          = "YaraTrix Enterprise"

    strings:
        $b1 = "bitsadmin" nocase ascii wide
        $b2 = "/transfer" nocase ascii wide
        $b3 = "/download" nocase ascii wide
        $b4 = "/addfile" nocase ascii wide
        
    condition:
        $b1 and any of ($b2, $b3, $b4)
}

rule PowerShell_Execution_Bypass {
    meta:
        mitre_technique = "T1059.001"
        mitre_tactic    = "execution"
        severity        = "high"
        description     = "Detects PowerShell execution policy bypass arguments"
        author          = "YaraTrix Enterprise"

    strings:
        $ps = "powershell" nocase ascii wide
        
        $ep1 = "-ExecutionPolicy Bypass" nocase ascii wide
        $ep2 = "-ep bypass" nocase ascii wide
        $ep3 = "-exec bypass" nocase ascii wide
        
        $w1 = "-WindowStyle Hidden" nocase ascii wide
        $w2 = "-w hidden" nocase ascii wide
        
        $nop = "-NoProfile" nocase ascii wide
        $nop2 = "-nop" nocase ascii wide
        
    condition:
        $ps and (any of ($ep*) or any of ($w*) or any of ($nop*))
}

rule LOLBin_Regsvr32_Scrobj {
    meta:
        mitre_technique = "T1218.010"
        mitre_tactic    = "defense-evasion"
        severity        = "high"
        description     = "Detects Squiblydoo attack using regsvr32.exe and scrobj.dll"
        author          = "YaraTrix Enterprise"

    strings:
        $r1 = "regsvr32" nocase ascii wide
        $r2 = "/s /n /u /i:" nocase ascii wide
        $r3 = "scrobj.dll" nocase ascii wide
        $r4 = "http" nocase ascii wide
        
    condition:
        all of them
}
