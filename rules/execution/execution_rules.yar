/*
    YaraTrix Execution Rules
    Tactic: Execution (TA0002)

    Covers:
      - Suspicious PowerShell encoded commands (T1059.001)
      - PowerShell download-and-execute patterns (T1059.001)
      - WMIC process call create (T1047)
      - Certutil abuse for downloading payloads (T1105 / T1059.003)
*/

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        mitre_technique  = "T1059.001"
        mitre_tactic     = "execution"
        severity         = "high"
        description      = "Detects PowerShell invocation with Base64-encoded command blocks, a common technique used by attackers to obfuscate malicious scripts."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Classic -EncodedCommand / -enc / -e flags
        $enc_flag1 = "-EncodedCommand" nocase wide ascii
        $enc_flag2 = " -enc " nocase wide ascii
        $enc_flag3 = " -e " nocase wide ascii
        $enc_flag4 = "/enc " nocase wide ascii

        // PowerShell invocations
        $ps_invoke1 = "powershell" nocase wide ascii
        $ps_invoke2 = "pwsh" nocase wide ascii

        // Base64 padding indicates encoded payload
        $b64_hint1 = "JAB" wide ascii   // Base64 "$" in UTF-16LE (common PS var)
        $b64_hint2 = "TVq" wide ascii   // MZ header in Base64 (embedded PE)
        $b64_hint3 = "SQBB" wide ascii  // 'I' in UTF-16LE Base64

    condition:
        any of ($ps_invoke*) and
        any of ($enc_flag*) and
        any of ($b64_hint*)
}


rule PowerShell_DownloadAndExecute
{
    meta:
        mitre_technique  = "T1059.001"
        mitre_tactic     = "execution"
        severity         = "high"
        description      = "Detects PowerShell scripts that combine a download method (Net.WebClient, Invoke-WebRequest, BitsTransfer) with execution, indicative of a dropper or stager."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Download mechanisms
        $dl1 = "Net.WebClient" nocase wide ascii
        $dl2 = "Invoke-WebRequest" nocase wide ascii
        $dl3 = "wget" nocase wide ascii
        $dl4 = "curl" nocase wide ascii
        $dl5 = "Start-BitsTransfer" nocase wide ascii
        $dl6 = "DownloadString" nocase wide ascii
        $dl7 = "DownloadFile" nocase wide ascii

        // Execution after download
        $exec1 = "Invoke-Expression" nocase wide ascii
        $exec2 = "IEX" wide ascii
        $exec3 = "Start-Process" nocase wide ascii
        $exec4 = "& {" wide ascii
        $exec5 = "Invoke-Item" nocase wide ascii

    condition:
        any of ($dl*) and any of ($exec*)
}


rule WMIC_Process_Create_Execution
{
    meta:
        mitre_technique  = "T1047"
        mitre_tactic     = "execution"
        severity         = "medium"
        description      = "Detects use of WMIC to create new processes, commonly used for lateral movement or to spawn child processes while bypassing standard execution controls."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        $wmic       = "wmic" nocase wide ascii
        $process    = "process" nocase wide ascii
        $call       = "call" nocase wide ascii
        $create     = "create" nocase wide ascii

    condition:
        all of them
}


rule Certutil_Payload_Download
{
    meta:
        mitre_technique  = "T1105"
        mitre_tactic     = "execution"
        severity         = "high"
        description      = "Detects certutil.exe being abused to download remote files or decode Base64 payloads, a well-known LOLBin (Living Off the Land Binary) technique."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        $certutil = "certutil" nocase wide ascii

        // Download mode
        $urlcache = "-urlcache" nocase wide ascii
        $split    = "-split" nocase wide ascii

        // Decode mode
        $decode   = "-decode" nocase wide ascii
        $f_flag   = "-f " nocase wide ascii

        // URL indicators
        $http     = "http://" nocase wide ascii
        $https    = "https://" nocase wide ascii

    condition:
        $certutil and
        (
            ($urlcache and ($http or $https)) or
            ($decode and ($split or $f_flag))
        )
}
