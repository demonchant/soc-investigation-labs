# Threat Hunting Lab (Proactive Detection of Hidden Attacks)

## Scenario

No alerts were triggered in the environment, but unusual behavior was suspected.  

As a SOC analyst, the goal is to proactively hunt for hidden threats by analyzing patterns in PowerShell execution, network activity, and authentication logs.

This lab simulates threat hunting to uncover stealthy attacker behavior that may bypass traditional detection rules.



## Hunting Hypothesis

Attackers may:
- Use PowerShell without obvious malicious flags  
- Communicate with multiple external IPs  
- Blend in with normal user behavior  
- Avoid repeated patterns to evade detection  

## Hunting Queries

### Hunt for Unusual PowerShell Usage

```spl
index=lab_logs EventID=4688 ProcessName="powershell.exe"
| stats count by Host ParentProcessName
| sort -count

### Hunt for Rare Parent Processes

index=lab_logs EventID=4688 ProcessName="powershell.exe"
| stats count by ParentProcessName
| where count < 3

### Hunt for Systems Talking to Many IPs

index=lab_logs EventID=3
| stats dc(DestinationIp) as unique_ips by Host
| where unique_ips > 3

### Hunt for Off-Hours Activity

index=lab_logs EventID=4688 ProcessName="powershell.exe"
| eval hour=strftime(_time,"%H")
| where hour < 6 OR hour > 22
| table _time Host ParentProcessName CommandLine

## Findings
A host (Finance-PC) showed unusual PowerShell activity
PowerShell was launched by an uncommon parent process
The system communicated with multiple external IPs
Some activity occurred outside normal working hours

## Analysis

No single event triggered an alert
However, combining multiple weak signals revealed suspicious behavior

### Key Insight:

Attackers may avoid detection by staying under thresholds
Hunting allows detection of these stealth techniques

## Conclusion:

This behavior is consistent with low-and-slow attacker activity
Indicates possible early-stage compromise or stealth persistence

## What Was Done

Investigated affected host (Finance-PC)
Monitored unusual PowerShell activity
Reviewed network connections
Escalated findings for deeper forensic analysis



