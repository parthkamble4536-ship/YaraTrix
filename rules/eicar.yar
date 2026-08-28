/*
    YaraTrix Standard Test Rules
    Tactic: Initial Access (TA0001)
*/

rule EICAR_Test_File {
    meta:
        mitre_technique = "T1566"
        mitre_tactic    = "initial-access"
        severity        = "critical"
        description     = "Standard Antivirus Test File (EICAR) - Safe to handle, used for testing engines"
        author          = "EICAR"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar
}
