/*
    YaraTrix Defense Evasion Rules
    Tactic: Defense Evasion (TA0005)

    Covers:
      - Process hollowing indicators (T1055.012)
      - Obfuscation markers in scripts (T1027)
      - AMSI bypass techniques (T1562.001)
      - Binary padding / PE anomalies (T1027.001)
*/

rule Process_Hollowing_Indicators
{
    meta:
        mitre_technique  = "T1055.012"
        mitre_tactic     = "defense-evasion"
        severity         = "critical"
        description      = "Detects process hollowing technique indicators: the classic API call sequence of CreateProcess(SUSPENDED) followed by NtUnmapViewOfSection, VirtualAllocEx, and ResumeThread used to inject a replacement PE into a legitimate process."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Process hollowing API sequence
        $create_susp    = "CREATE_SUSPENDED" nocase wide ascii
        $create_susp2   = "0x00000004" wide ascii   // CREATE_SUSPENDED flag value

        $unmap          = "NtUnmapViewOfSection" nocase wide ascii
        $unmap2         = "ZwUnmapViewOfSection" nocase wide ascii

        $valloc         = "VirtualAllocEx" nocase wide ascii
        $wpm            = "WriteProcessMemory" nocase wide ascii
        $set_ctx        = "SetThreadContext" nocase wide ascii
        $resume         = "ResumeThread" nocase wide ascii

        // Process creation targets
        $target1        = "svchost.exe" nocase wide ascii
        $target2        = "explorer.exe" nocase wide ascii
        $target3        = "notepad.exe" nocase wide ascii

    condition:
        // Full hollowing chain: unmap + alloc + write + resume
        (any of ($unmap*) and $valloc and $wpm and $resume) or
        // Suspended create + context set (earmarks early hollowing)
        (any of ($create_susp*) and $set_ctx and $resume and any of ($target*))
}


rule Script_Obfuscation_Markers
{
    meta:
        mitre_technique  = "T1027"
        mitre_tactic     = "defense-evasion"
        severity         = "medium"
        description      = "Detects common obfuscation patterns in scripts: excessive string splitting/joining, character code arrays, variable name randomization patterns, and reversed strings — techniques used to evade signature-based detection."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // PowerShell obfuscation patterns
        $split_join     = "-join" nocase wide ascii
        $char_array     = "[char[]]" nocase wide ascii
        $char_cast      = "[char]" nocase wide ascii
        $xor_loop       = "-bxor" nocase wide ascii          // PowerShell XOR
        $replace_chain  = "replace" nocase wide ascii

        // Invoke obfuscation
        $iex_obf1       = "I`E`X" nocase wide ascii          // Backtick escape
        $iex_obf2       = "I\"+\"EX" nocase wide ascii       // String concat
        $invoke_hidden  = "[ScriptBlock]::Create" nocase wide ascii

        // VBScript/JScript obfuscation
        $chr_func       = "Chr(" nocase wide ascii           // VBScript char lookup
        $chr_w          = "ChrW(" nocase wide ascii
        $string_reverse = "StrReverse" nocase wide ascii

        // Generic: lots of percent-encoding or hex escapes
        $pct_encode     = /(%[0-9a-fA-F]{2}){8,}/           // 8+ URL-encoded bytes
        $hex_escape     = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}/  // 8+ hex escapes

    condition:
        // Needs at least 3 distinct obfuscation signals
        (
            ($split_join and $char_array) or
            ($xor_loop and $char_cast) or
            ($iex_obf1 or $iex_obf2) or
            ($invoke_hidden and $replace_chain)
        ) or
        2 of ($chr_func, $chr_w, $string_reverse) or
        any of ($pct_encode, $hex_escape)
}


rule AMSI_Bypass_Techniques
{
    meta:
        mitre_technique  = "T1562.001"
        mitre_tactic     = "defense-evasion"
        severity         = "high"
        description      = "Detects attempts to bypass the Antimalware Scan Interface (AMSI), which attackers disable to prevent Windows Defender and other AV products from inspecting PowerShell and .NET script execution."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Direct AMSI patching
        $amsi_ctx       = "AmsiContext" nocase wide ascii
        $amsi_scan      = "AmsiScanBuffer" nocase wide ascii
        $amsi_init      = "AmsiInitialize" nocase wide ascii
        $amsi_dll       = "amsi.dll" nocase wide ascii

        // Common patch bytes written to AmsiScanBuffer (ret 0 / mov eax,0x80070057)
        $patch1         = { B8 57 00 07 80 C3 }   // mov eax,0x80070057; ret
        $patch2         = { B8 34 12 07 80 C3 }   // variant
        $patch3         = { 31 C0 C3 }             // xor eax,eax; ret

        // PowerShell reflection to find/patch AMSI
        $ps_ref1        = "[Ref].Assembly.GetType" nocase wide ascii
        $ps_ref2        = "GetField" nocase wide ascii
        $ps_ref3        = "SetValue($null" nocase wide ascii
        $ps_ref4        = "NonPublic,Static" nocase wide ascii

        // Disabling ETW (Event Tracing for Windows) — often paired with AMSI bypass
        $etw1           = "EtwEventWrite" nocase wide ascii
        $etw2           = "EtwEventSend" nocase wide ascii

    condition:
        any of ($amsi_ctx, $amsi_scan, $amsi_init, $amsi_dll) and
        (
            any of ($patch*) or
            (2 of ($ps_ref*)) or
            any of ($etw*)
        )
}


rule PE_Binary_Padding_Anomaly
{
    meta:
        mitre_technique  = "T1027.001"
        mitre_tactic     = "defense-evasion"
        severity         = "low"
        description      = "Detects PE files with unusual size anomalies caused by binary padding — a technique used to inflate malware file size above AV scanning thresholds. Indicates potential packing or anti-analysis measures."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Valid PE header magic
        $mz_header      = { 4D 5A }                        // MZ
        $pe_sig         = { 50 45 00 00 }                  // PE\0\0

        // Large nullbyte padding blocks (100+ consecutive zero bytes)
        $null_pad       = { 00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00
                            00 00 00 00 00 00 00 00 }

        // Common packer signatures
        $upx            = "UPX!" wide ascii
        $petite         = "PEtite" nocase wide ascii
        $nsis           = "Nullsoft" nocase wide ascii

    condition:
        $mz_header at 0 and $pe_sig and
        (
            (#null_pad >= 3 and filesize > 5MB) or
            any of ($upx, $petite, $nsis)
        )
}
