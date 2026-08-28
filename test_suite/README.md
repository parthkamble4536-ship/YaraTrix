# YaraTrix Threat Intelligence Platform - Test Suite

This directory contains test files specifically designed to trigger the various YARA rules loaded into your `rules/` directory. By scanning these files in your newly redesigned dashboard, you can verify how different tactics, techniques, and severities are visualized on the frontend.

## Included Test Samples:

1. **`mimikatz_dump.c`**
   - **Expected Result**: **CRITICAL Severity**
   - **Rules Triggered**: `Mimikatz_Indicators` and `LSASS_Memory_Access`
   - **Tactics**: Credential Access
   - **Description**: Triggers multiple Mimikatz signatures and LSASS memory dumping APIs.

2. **`sam_dump.bat`**
   - **Expected Result**: **CRITICAL Severity**
   - **Rules Triggered**: `SAM_Database_Dump`
   - **Tactics**: Credential Access
   - **Description**: A batch script attempting to dump the SAM database via registry saves and VSS shadow copies.

3. **`vault_access.ps1`**
   - **Expected Result**: **HIGH Severity**
   - **Rules Triggered**: `Credential_Vault_Access`
   - **Tactics**: Credential Access
   - **Description**: A PowerShell script attempting to enumerate the Windows Credential Manager / Vault.

4. **`obfuscated.ps1`**
   - **Expected Result**: **HIGH Severity**
   - **Rules Triggered**: `Suspicious_PowerShell_EncodedCommand` and `Defense_Evasion_Obfuscated_Script`
   - **Tactics**: Execution, Defense Evasion
   - **Description**: Contains encoded PowerShell commands and character substitution obfuscation.

5. **`discovery_persistence.bat`**
   - **Expected Result**: **MEDIUM Severity**
   - **Rules Triggered**: `Discovery_System_Info` and `Persistence_Registry_Run_Key`
   - **Tactics**: Discovery, Persistence
   - **Description**: Contains `systeminfo`, `wmic`, and a registry `Run` key installation.

6. **`clean_file.txt`**
   - **Expected Result**: **CLEAN (No Threats)**
   - **Rules Triggered**: None
   - **Description**: A completely safe file to test the "0 threats detected" visual state in the dashboard.

## How to Test:
1. Open your browser to `http://localhost:3000/scan`.
2. Drag and drop any of these files into the upload zone.
3. Observe the radar scanning animation, followed by the generated Intelligence Report and Severity Distribution.
4. Navigate to `http://localhost:3000/analytics` to see how these scans update your Rule Effectiveness scores in real-time!
