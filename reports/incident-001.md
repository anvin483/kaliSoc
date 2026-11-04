# Incident 001: PowerShell CLM Registry Modification

## Evidence
- Host: DC1.insecurebank.local
- Event Source: Microsoft-Windows-Sysmon
- Event ID: 12
- Record ID: 18527
- Date: 2019-05-16 13:10:13 UTC
- Process: powershell.exe
- Process ID: 3580
- User SID: S-1-5-18

## Observed Activity
A PowerShell process deleted the registry value:

HKLM\System\CurrentControlSet\Control\
Session Manager\Environment\__PSLockdownPolicy

## Preliminary Assessment
Potential PowerShell security configuration
tampering.

## Investigation Status
Pending process lineage and surrounding event
correlation.

## Detection Tool
Chainsaw 2.17.1

