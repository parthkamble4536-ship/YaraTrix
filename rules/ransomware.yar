/*
    YaraTrix Ransomware & Cryptojacking Rules
    Tactic: Impact (TA0040)
*/

rule Ransomware_WannaCry {
    meta:
        mitre_technique = "T1486"
        mitre_tactic    = "impact"
        severity        = "critical"
        description     = "Detects WannaCry ransomware specific strings, killswitch domain, and encryption indicators"
        author          = "YaraTrix Enterprise"

    strings:
        $s1 = "WNcry@2ol7" ascii
        $s2 = "msg/m_english.wnry" ascii wide
        $s3 = "WannaDecryptor" ascii wide
        $s4 = "tasksche.exe" ascii wide
        $s5 = "icacls . /grant Everyone:F /T /C /Q" ascii
        $s6 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $s7 = "mssecsvc.exe" ascii wide
        $s8 = ".wnry" ascii wide
        $s9 = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $mz = "MZ"

    condition:
        $mz at 0 and 2 of ($s*)
}

rule Ransomware_LockBit {
    meta:
        mitre_technique = "T1486"
        mitre_tactic    = "impact"
        severity        = "critical"
        description     = "Detects LockBit 2.0/3.0 ransomware strings and behaviors"
        author          = "YaraTrix Enterprise"

    strings:
        $lb1 = "LockBit" ascii wide
        $lb2 = "Restore-My-Files.txt" ascii wide
        $lb3 = "SOFTWARE\\LockBit" nocase ascii wide
        $lb4 = "Tox ID" ascii wide
        
        $vss = "vssadmin delete shadows /all /quiet" ascii wide
        $mz = "MZ"
        
    condition:
        $mz at 0 and (2 of ($lb*) or $vss)
}

rule Ransomware_Ryuk {
    meta:
        mitre_technique = "T1486"
        mitre_tactic    = "impact"
        severity        = "critical"
        description     = "Detects Ryuk ransomware indicators including ransom notes and internal paths"
        author          = "YaraTrix Enterprise"

    strings:
        $s1 = "RyukReadMe.txt" ascii wide
        $s2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $s3 = "hermes" nocase ascii wide
        $s4 = "No system is safe" ascii wide
        $mz = "MZ"
        
    condition:
        $mz at 0 and 2 of ($s*)
}

rule Malware_XMRig_Miner {
    meta:
        mitre_technique = "T1496"
        mitre_tactic    = "impact"
        severity        = "high"
        description     = "Detects XMRig Monero CPU miner often used in cryptojacking campaigns"
        author          = "YaraTrix Enterprise"

    strings:
        $x1 = "XMRig" ascii wide nocase
        $x2 = "stratum+tcp://" ascii wide
        $x3 = "monero" ascii wide nocase
        $x4 = "* COMMANDS: 'h' hashrate, 'p' pause, 'r' resume, 's' results, 'c' connection" ascii
        $x5 = "donate.v2.xmrig.com" ascii wide
        $mz = "MZ"
        
    condition:
        $mz at 0 and 3 of ($x*)
}
