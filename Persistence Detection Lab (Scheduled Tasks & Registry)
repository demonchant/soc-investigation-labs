# Persistence Detection Lab (Scheduled Tasks & Registry)

## Scenario

Suspicious activity was detected on host `Finance-PC` following PowerShell execution.  
Further investigation revealed the creation of a scheduled task designed to maintain persistence on the system.

This lab simulates detection of persistence mechanisms using Windows logs in Splunk.


## Logs / Evidence

Here’s what was observed:

| _time | EventID | Host        | ProcessName     | TaskName              |
|------|--------|------------|----------------|-----------------------|
| 14:10 | 4688 | Finance-PC  | powershell.exe | -                     |
| 14:12 | 4698 | Finance-PC  | powershell.exe | UpdateServiceTask     |
| 14:13 | 4698 | Finance-PC  | powershell.exe | UpdateServiceTask     |
| 14:20 | 4688 | Finance-PC  | powershell.exe | -                     |


## Detection Queries

### Detect Scheduled Task Creation

```spl
index=lab_logs EventID=4698
| table _time Host TaskName CommandLine

## Detect Suspicious Task Creation via PowerShell

index=lab_logs EventID=4698
| search CommandLine="*powershell*" OR CommandLine="*cmd*"
| table _time Host TaskName CommandLine

## Correlate PowerShell Execution with Persistence

index=lab_logs (EventID=4688 OR EventID=4698)
| stats values(EventID) as Events by Host TaskName CommandLine

## Analysis

Initial PowerShell execution was observed on Finance-PC.
Shortly after, a scheduled task named UpdateServiceTask was created.

### Key Observations:

Task created using PowerShell
Repeated creation of same task
Task name appears legitimate but is suspicious in context

### Pattern Observed:

Execution → Persistence
Task ensures malware runs again even after reboot

## Conclusion:

This behavior indicates persistence via scheduled tasks.
The attacker has established a mechanism to maintain access to the system.
What Was Done
Suspicious scheduled task (UpdateServiceTask) was removed
Affected host was isolated
PowerShell activity was further investigated
Credentials were reset
System monitored for re-infection attempts

