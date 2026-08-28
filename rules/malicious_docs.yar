/*
    YaraTrix Phishing & Malicious Documents Rules
    Tactic: Initial Access (TA0001) / Execution (TA0002)
*/

rule Malicious_Office_Macro_VBA {
    meta:
        mitre_technique = "T1566.001"
        mitre_tactic    = "initial-access"
        severity        = "high"
        description     = "Detects suspicious VBA macro executions in Office documents"
        author          = "YaraTrix Enterprise"

    strings:
        $vba1 = "AutoOpen" nocase ascii wide
        $vba2 = "Document_Open" nocase ascii wide
        $vba3 = "AutoExec" nocase ascii wide
        
        $susp1 = "Shell(" nocase ascii wide
        $susp2 = "WScript.Shell" nocase ascii wide
        $susp3 = "CreateObject" nocase ascii wide
        $susp4 = "powershell.exe" nocase ascii wide
        $susp5 = "cmd.exe /c" nocase ascii wide
        
        // Document Magic bytes (OLE or ZIP/DOCX)
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }
        
    condition:
        ($ole at 0 or $zip at 0) and
        (any of ($vba*)) and
        (2 of ($susp*))
}

rule Suspicious_PDF_JavaScript {
    meta:
        mitre_technique = "T1566.001"
        mitre_tactic    = "initial-access"
        severity        = "medium"
        description     = "Detects PDFs containing embedded JavaScript or auto-launch actions"
        author          = "YaraTrix Enterprise"

    strings:
        $pdf = "%PDF-" ascii
        
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $js3 = "/OpenAction" ascii
        $js4 = "/Launch" ascii
        
    condition:
        $pdf at 0 and ($js1 or $js2) and ($js3 or $js4)
}

rule Emotet_Word_Doc {
    meta:
        mitre_technique = "T1566.001"
        mitre_tactic    = "initial-access"
        severity        = "critical"
        description     = "Detects Emotet maldoc characteristics"
        author          = "YaraTrix Enterprise"

    strings:
        $e1 = "powershell -e" nocase ascii wide
        $e2 = "WMI" nocase ascii wide
        $e3 = "winmgmts:" nocase ascii wide
        $e4 = "Win32_Process" nocase ascii wide
        
        $doc = { D0 CF 11 E0 A1 B1 1A E1 }
        
    condition:
        $doc at 0 and 3 of ($e*)
}
