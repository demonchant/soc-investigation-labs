# Detection Engineering Lab (Building SOC Detection Rules in Splunk)

## Scenario

After investigating multiple attack patterns (phishing, PowerShell abuse, beaconing, brute force, and lateral movement), the goal is to convert these findings into automated detection rules.

This lab simulates how a SOC analyst creates reusable detection logic to identify threats in real time.


## Objective

Develop detection rules for:

- Malicious PowerShell execution  
- Beaconing behavior  
- Brute force login attempts  
- Lateral movement activity  



## Detection Rules

### Rule 1 — Suspicious PowerShell Execution

```spl
index=lab_logs EventID=4688 ProcessName="powershell.exe"
| search ParentProcessName IN ("winword.exe","excel.exe","outlook.exe")
   OR CommandLine="*enc*" OR CommandLine="*hidden*" OR CommandLine="*bypass*"


### Trigger Condition:

Any result returned

### Severity:

High


### Rule 2 — Beaconing Detection

index=lab_logs EventID=3 ProcessName="powershell.exe"
| stats count min(_time) as firstSeen max(_time) as lastSeen by Host DestinationIp
| eval duration = lastSeen - firstSeen
| where count >= 5 AND duration <= 600

### Trigger Condition:

Repeated connections to same IP within short time

### Severity:

High

### Rule 3 — Brute Force Detection

index=lab_logs EventID=4625
| stats count by Account_Name SourceIp
| where count >= 5

### Trigger Condition:

Multiple failed logins

### Severity:

Medium

### Rule 4 — Lateral Movement Detection

index=lab_logs EventID=4688 ProcessName="powershell.exe"
| search ParentProcessName IN ("wmiprvse.exe","psexec.exe","services.exe")

### Trigger Condition:

PowerShell launched by remote execution processes

### Severity:

High

## Implementation

Each detection rule can be configured in Splunk as:

Saved Search
Alert Trigger
Scheduled Detection

Example:

Run every 5 minutes
Trigger alert when conditions are met
Send notification to SOC team

## Analysis

These rules are based on real attack behaviors observed in previous labs
Each rule targets a specific stage of the attack lifecycle

### Coverage Includes:
Initial access (phishing)
Execution (PowerShell)
Persistence
Lateral movement
Command-and-control

### Key Insight:
Detection engineering transforms manual investigations into automated defense

## What Was Done
Created detection rules for multiple attack scenarios
Defined thresholds and trigger conditions
Structured alerts based on severity levels
Prepared rules for continuous monitoring
