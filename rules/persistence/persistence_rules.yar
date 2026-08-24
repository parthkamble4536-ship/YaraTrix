/*
    YaraTrix Persistence Rules
    Tactic: Persistence (TA0003)

    Covers:
      - Registry Run key writes (T1547.001)
      - Scheduled task creation via cmd/schtasks (T1053.005)
      - Startup folder abuse (T1547.001)
      - WMI event subscription persistence (T1546.003)
*/

rule Registry_Run_Key_Persistence
{
    meta:
        mitre_technique  = "T1547.001"
        mitre_tactic     = "persistence"
        severity         = "high"
        description      = "Detects writes to common Registry Run keys used to achieve boot-time or logon persistence. Malware frequently writes to HKCU or HKLM Run/RunOnce to survive reboots."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // Run key paths
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
        $run3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" nocase wide ascii
        $run4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $run5 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii

        // Registry write APIs / commands
        $write1 = "RegSetValueEx" nocase wide ascii
        $write2 = "reg add" nocase wide ascii
        $write3 = "Set-ItemProperty" nocase wide ascii  // PowerShell registry write

    condition:
        any of ($run*) and any of ($write*)
}


rule Scheduled_Task_Creation
{
    meta:
        mitre_technique  = "T1053.005"
        mitre_tactic     = "persistence"
        severity         = "high"
        description      = "Detects scheduled task creation via schtasks.exe or the PowerShell New-ScheduledTask cmdlets, which attackers use to establish persistence or trigger payloads on a schedule."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // schtasks binary and sub-commands
        $schtasks = "schtasks" nocase wide ascii
        $create   = "/create" nocase wide ascii
        $sc_cmd   = "/sc " nocase wide ascii
        $tr_cmd   = "/tr " nocase wide ascii

        // PowerShell equivalents
        $ps_new   = "New-ScheduledTask" nocase wide ascii
        $ps_reg   = "Register-ScheduledTask" nocase wide ascii

        // Trigger indicators
        $trig1    = "ONLOGON" nocase wide ascii
        $trig2    = "ONSTART" nocase wide ascii
        $trig3    = "DAILY" nocase wide ascii
        $trig4    = "MINUTE" nocase wide ascii

    condition:
        (
            ($schtasks and $create and ($sc_cmd or $tr_cmd)) or
            ($ps_new or $ps_reg)
        ) and any of ($trig*)
}


rule Startup_Folder_Persistence
{
    meta:
        mitre_technique  = "T1547.001"
        mitre_tactic     = "persistence"
        severity         = "medium"
        description      = "Detects references to Windows Startup folder paths used to place executables or shortcuts that run automatically on user logon."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        $startup1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase wide ascii
        $startup2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase wide ascii
        $startup3 = "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" nocase wide ascii

        // Write or copy operations
        $copy1 = "Copy-Item" nocase wide ascii
        $copy2 = "xcopy" nocase wide ascii
        $copy3 = "CopyFile" nocase wide ascii
        $copy4 = "MoveFile" nocase wide ascii
        $copy5 = "cp " wide ascii

    condition:
        any of ($startup*) and any of ($copy*)
}


rule WMI_Event_Subscription_Persistence
{
    meta:
        mitre_technique  = "T1546.003"
        mitre_tactic     = "persistence"
        severity         = "critical"
        description      = "Detects WMI event subscription patterns used to achieve stealthy persistence. WMI subscriptions survive reboots and are often missed by traditional AV scanners."
        author           = "YaraTrix"
        version          = "1.0"

    strings:
        // WMI subscription classes
        $wmi_filter     = "__EventFilter" wide ascii
        $wmi_consumer   = "CommandLineEventConsumer" nocase wide ascii
        $wmi_consumer2  = "ActiveScriptEventConsumer" nocase wide ascii
        $wmi_binding    = "__FilterToConsumerBinding" wide ascii

        // WMI creation patterns
        $create1 = "Set-WmiInstance" nocase wide ascii
        $create2 = "New-Object System.Management.ManagementObject" nocase wide ascii
        $create3 = "CreateInstance" nocase wide ascii

        // Trigger condition strings
        $trigger1 = "SELECT * FROM __InstanceCreationEvent" nocase wide ascii
        $trigger2 = "Win32_ProcessStartTrace" nocase wide ascii
        $trigger3 = "TimerEvent" nocase wide ascii

    condition:
        any of ($wmi_filter, $wmi_consumer, $wmi_consumer2, $wmi_binding) and
        (any of ($create*) or any of ($trigger*))
}
