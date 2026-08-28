/*
    YaraTrix Command & Control / Post-Exploitation Rules
    Tactic: Command and Control (TA0011)
*/

rule C2_CobaltStrike_Beacon {
    meta:
        mitre_technique = "T1071.001"
        mitre_tactic    = "command-and-control"
        severity        = "critical"
        description     = "Detects Cobalt Strike beacon payload strings and default configurations"
        author          = "YaraTrix Enterprise"

    strings:
        $cs1 = "beacon.dll" ascii wide
        $cs2 = "%s as %s\\%s: %d" ascii
        $cs3 = "HTTP/1.1 200 OK" ascii
        $cs4 = "Server: Apache" ascii
        $cs5 = "Content-Type: application/octet-stream" ascii
        
        $pipe = "\\\\.\\pipe\\MSSE-" ascii
        $mz = "MZ"
        
    condition:
        $mz at 0 and
        ($pipe or 3 of ($cs*))
}

rule C2_Metasploit_Meterpreter {
    meta:
        mitre_technique = "T1059"
        mitre_tactic    = "execution"
        severity        = "critical"
        description     = "Detects Metasploit Meterpreter reverse TCP and HTTP/S payloads"
        author          = "YaraTrix Enterprise"

    strings:
        $m1 = "meterpreter" nocase ascii wide
        $m2 = "metsrv.dll" nocase ascii wide
        $m3 = "WS2_32.dll" nocase ascii wide
        
        // Reverse TCP stub patterns
        $rev_tcp = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 00 00 }
        $mz = "MZ"
        
    condition:
        $mz at 0 and (2 of ($m*) or $rev_tcp)
}

rule C2_Sliver_Framework {
    meta:
        mitre_technique = "T1071"
        mitre_tactic    = "command-and-control"
        severity        = "high"
        description     = "Detects Sliver C2 framework implants (Golang)"
        author          = "YaraTrix Enterprise"

    strings:
        $go1 = "Go build ID:" ascii
        $go2 = "sliverpb." ascii
        $go3 = "github.com/bishopfox/sliver" ascii
        $go4 = "sliver/client" ascii
        $mz = "MZ"
        
    condition:
        $mz at 0 and $go1 and 2 of ($go2, $go3, $go4)
}
