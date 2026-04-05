# Incident Response Playbook (Phishing → PowerShell → C2 Attack)

## Scenario

A multi-stage attack was detected involving phishing, PowerShell execution, command-and-control communication, persistence, and potential lateral movement.

This playbook outlines the step-by-step response actions a SOC analyst should take to investigate and contain the incident.

---

## Objective

Provide a structured response to:

- Detect  
- Investigate  
- Contain  
- Eradicate  
- Recover  

---

## Phase 1 — Detection

### Indicators Observed

- PowerShell execution from `winword.exe`  
- Encoded/hidden PowerShell commands  
- Repeated outbound connections to external IP  
- Scheduled task creation  
- Failed login attempts  

---

## Phase 2 — Investigation

### Step 1 — Confirm Suspicious Execution

```spl
index=lab_logs EventID=4688 ProcessName="powershell.exe"
| table _time Host ParentProcessName CommandLineStep 2 — Check Network Activity

### Step 2 — Check Network Activity

index=lab_logs EventID=3
| stats count by Host DestinationIp

### Step 3 — Identify Persistence

index=lab_logs EventID=4698
| table _time Host TaskName CommandLine

### Step 4 — Check for Lateral Movement

index=lab_logs EventID=4688
| search ParentProcessName IN ("wmiprvse.exe","psexec.exe")

### Step 5 — Review Authentication Activity

index=lab_logs EventID=4625
| stats count by Account_Name SourceIp

## Phase 3 — Containment

Isolate affected host(s) from network
Block malicious IP addresses
Disable compromised user accounts
Stop malicious processes

## Phase 4 — Eradication

Remove scheduled tasks
Delete malicious files/scripts
Clear persistence mechanisms
Patch vulnerabilities if identified

## Phase 5 — Recovery

Restore system to clean state
Reconnect host to network
Monitor for re-infection
Validate normal system behavior

## Phase 6 — Lessons Learned

Improve email filtering rules
Enhance PowerShell monitoring
Deploy detection rules for beaconing
Train users on phishing awareness
