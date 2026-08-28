/*
    YaraTrix Web Shells & Exploits Rules
    Tactic: Initial Access (TA0001) / Persistence (TA0003)
*/

rule Webshell_ChinaChopper {
    meta:
        mitre_technique = "T1505.003"
        mitre_tactic    = "persistence"
        severity        = "critical"
        description     = "Detects China Chopper one-liner web shells (PHP/ASP/JSP)"
        author          = "YaraTrix Enterprise"

    strings:
        $php = "@eval($_POST[" ascii
        $asp = "eval request(" nocase ascii
        $jsp = "Runtime.getRuntime().exec(request.getParameter(" ascii
        $password = "z0" ascii // Default chopper password
        
    condition:
        any of ($php, $asp, $jsp) or ($password and any of ($php, $asp, $jsp))
}

rule Exploit_Log4Shell_CVE_2021_44228 {
    meta:
        mitre_technique = "T1190"
        mitre_tactic    = "initial-access"
        severity        = "critical"
        description     = "Detects Log4j JNDI lookup exploitation strings (CVE-2021-44228)"
        author          = "YaraTrix Enterprise"

    strings:
        $jndi1 = "${jndi:ldap://" nocase ascii
        $jndi2 = "${jndi:rmi://" nocase ascii
        $jndi3 = "${jndi:ldaps://" nocase ascii
        $jndi4 = "${jndi:dns://" nocase ascii
        
        // Obfuscated variations
        $obf1 = "${${lower:j}ndi:" nocase ascii
        $obf2 = "${jndi:${lower:l}${lower:d}a${lower:p}://" nocase ascii
        
    condition:
        any of them
}

rule Webshell_Generic_PHP {
    meta:
        mitre_technique = "T1505.003"
        mitre_tactic    = "persistence"
        severity        = "high"
        description     = "Detects generic PHP web shell functions commonly abused"
        author          = "YaraTrix Enterprise"

    strings:
        $f1 = "shell_exec(" ascii
        $f2 = "passthru(" ascii
        $f3 = "system(" ascii
        $f4 = "base64_decode(" ascii
        $f5 = "preg_replace(\"/.*/e\"" ascii
        
        $html = "<form" nocase ascii
        
    condition:
        (3 of ($f*)) and $html
}
