Scenario

Multiple security alerts were triggered in the environment involving PowerShell execution, failed logins, and network connections.

Objective: Simulate how a SOC analyst triages alerts, investigates activity, and classifies incidents based on severity.

Alerts Observed
Alert ID	Event Type	Host	Details
A1	PowerShell Execution	Finance-PC	winword.exe → powershell.exe
A2	Network Connection	Finance-PC	Repeated traffic to 45.77.12.90
A3	Failed Login	HR-PC	Multiple failed logins (admin)
A4	Scheduled Task	Finance-PC	Task created: UpdateServiceTask
Detection Queries
PowerShell Execution
index=lab_logs EventID=4688 ProcessName="powershell.exe"
| table _time Host ParentProcessName CommandLine Network Beaconing

index=lab_logs EventID=3 ProcessName="powershell.exe"
| stats count by DestinationIp
Failed Logins
index=lab_logs EventID=4625
| stats count by Host Account_Name
Scheduled Task Creation
index=lab_logs EventID=4698
| table _time Host TaskName CommandLine
Investigation & Classification
Alert A1 — PowerShell Execution
Parent Process: winword.exe
Command Line: Encoded / Hidden execution
Classification: Malicious
Reason: Office application spawning PowerShell indicates phishing-based execution.
Alert A2 — Network Connections
Destination IP: 45.77.12.90
Behavior: Repeated connections at regular intervals
Classification: Malicious
Reason: Consistent with command-and-control (C2) beaconing.
Alert A3 — Failed Logins
Target Account: admin
Behavior: Multiple failed attempts from the same source IP
Classification: Suspicious
Reason: Indicates brute force attempt, requires monitoring and response.
Alert A4 — Scheduled Task
Task Name: UpdateServiceTask
Triggered By: PowerShell
Classification: Malicious
Reason: Persistence mechanism established post-compromise.
Final Assessment
Correlated Alerts: Multiple alerts observed on Finance-PC
Attack Chain Identified:
Phishing → PowerShell Execution
C2 Communication
Persistence via Scheduled Task
Additional Activity: Failed logins detected on HR-PC

Conclusion: Confirmed system compromise; evidence of a multi-stage attack lifecycle.

Response Actions
Isolated affected systems (Finance-PC, HR-PC)
Blocked malicious IP: 45.77.12.90
Removed scheduled task
Reset compromised credentials
Initiated full environment scan
