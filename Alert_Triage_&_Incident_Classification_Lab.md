# SOC Alert Triage & Incident Classification Lab

## Scenario

Multiple security alerts were triggered in the environment involving PowerShell execution, failed logins, and network connections.  

The objective of this lab is to simulate how a SOC analyst triages alerts, investigates activity, and classifies incidents based on severity.


## Alerts Observed

| Alert ID | Event Type            | Host        | Details |
|---------|---------------------|------------|--------|
| A1      | PowerShell Execution | Finance-PC | winword.exe → powershell.exe |
| A2      | Network Connection   | Finance-PC | Repeated traffic to 45.77.12.90 |
| A3      | Failed Login         | HR-PC      | Multiple failed logins (admin) |
| A4      | Scheduled Task       | Finance-PC | Task created: UpdateServiceTask |


## Detection Queries

### PowerShell Execution

```spl
index=lab_logs EventID=4688 ProcessName="powershell.exe"
| table _time Host ParentProcessName CommandLineNetwork Beaconing
index=lab_logs EventID=3 ProcessName="powershell.exe"
| stats count by DestinationIp

### Failed Logins

index=lab_logs EventID=4625
| stats count by Host Account_Name

###Scheduled Task Creation

index=lab_logs EventID=4698
| table _time Host TaskName CommandLine

## Investigation & Classification

Alert A1 — PowerShell Execution
Parent Process: winword.exe
Command Line: Encoded / Hidden execution

Classification:  Malicious
Reason: Office application spawning PowerShell indicates phishing-based execution.

Alert A2 — Network Connections
Repeated connections to 45.77.12.90
Regular intervals observed

Classification:  Malicious
Reason: Consistent with command-and-control (C2) beaconing.

Alert A3 — Failed Logins
Multiple failed attempts on admin account
Same source IP

Classification:  Suspicious
Reason: Indicates brute force attempt, requires monitoring and response.

Alert A4 — Scheduled Task
Task created: UpdateServiceTask
Triggered by PowerShell

Classification:  Malicious
Reason: Persistence mechanism established post-compromise.

## Final Assessment
Multiple correlated alerts observed on Finance-PC
Attack chain identified:
Phishing → PowerShell Execution
C2 Communication
Persistence via Scheduled Task
Additional activity detected on HR-PC (failed logins)

## Conclusion:

Confirmed system compromise
Evidence of multi-stage attack lifecycle

## Response Actions

Isolated affected systems (Finance-PC, HR-PC)
Blocked malicious IP 45.77.12.90
Removed scheduled task
Reset compromised credentials
Initiated full environment scan
