# MITRE ATT&CK Mapping Lab (SOC Investigation Alignment)

## Scenario

Following multiple investigations (phishing, PowerShell execution, beaconing, brute force, lateral movement, persistence, and data exfiltration), the objective is to map observed attacker behavior to the MITRE ATT&CK framework.

This lab demonstrates how SOC analysts align real-world detections with standardized attack techniques.


## Objective

Map detected activities to MITRE ATT&CK tactics and techniques to improve:

- Threat understanding  
- Detection coverage  
- Incident reporting  


## Observed Attack Chain

- Phishing email delivery  
- Microsoft Word spawning PowerShell  
- Encoded command execution  
- Command-and-control (C2) communication  
- Scheduled task persistence  
- Lateral movement via WMI  
- Data exfiltration  


## MITRE ATT&CK Mapping

| Stage | Technique | Description |
|------|----------|------------|
| Initial Access | T1566 | Phishing |
| Execution | T1059.001 | PowerShell execution |
| Defense Evasion | T1027 | Obfuscated / Encoded Commands |
| Command & Control | T1071.001 | Web Protocol (HTTPS) |
| Persistence | T1053.005 | Scheduled Task |
| Lateral Movement | T1047 | Windows Management Instrumentation (WMI) |
| Credential Access | T1110 | Brute Force |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |


## Detection Mapping

### PowerShell Execution

```spl
index=lab_logs EventID=4688 ProcessName="powershell.exe"

MITRE Technique: T1059.001

Encoded Commands
index=lab_logs EventID=4688
| search CommandLine="*enc*"

MITRE Technique: T1027

Beaconing (C2)
index=lab_logs EventID=3
| stats count by DestinationIp

MITRE Technique: T1071.001

Persistence (Scheduled Task)
index=lab_logs EventID=4698

MITRE Technique: T1053.005

Lateral Movement (WMI)
index=lab_logs EventID=4688
| search ParentProcessName="wmiprvse.exe"

MITRE Technique: T1047

Brute Force
index=lab_logs EventID=4625

MITRE Technique: T1110

## Analysis

The attack spans multiple MITRE ATT&CK tactics
Each stage aligns with known adversary techniques
Key Insight:
Mapping detections to MITRE improves visibility into attack coverage
Helps identify gaps in detection capabilities

## Conclusion:

The observed activity represents a multi-stage attack lifecycle aligned with MITRE ATT&CK framework
What Was Done
Mapped attack behaviors to MITRE techniques
Linked detection queries to specific attack stages
Structured findings using industry-standard framework
