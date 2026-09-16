# Data Exfiltration Detection Lab

## Scenario

Unusual outbound network activity was detected from host `Finance-PC`.  
The system initiated multiple outbound connections to an external IP, transferring data over a short period.

This lab simulates detection of potential data exfiltration using network logs in Splunk.


## Logs / Evidence

Here’s what was observed:

| _time | EventID | Host        | ProcessName     | DestinationIp | BytesTransferred |
|------|--------|------------|----------------|--------------|------------------|
| 16:10 | 3    | Finance-PC  | powershell.exe | 45.77.12.90  | 500KB            |
| 16:11 | 3    | Finance-PC  | powershell.exe | 45.77.12.90  | 700KB            |
| 16:12 | 3    | Finance-PC  | powershell.exe | 45.77.12.90  | 1.2MB            |
| 16:13 | 3    | Finance-PC  | powershell.exe | 45.77.12.90  | 2MB              |
| 16:14 | 3    | Finance-PC  | powershell.exe | 45.77.12.90  | 3MB              |


## Detection Queries

### Detect High Outbound Traffic

```spl
index=lab_logs EventID=3
| stats sum(BytesTransferred) as total_bytes by Host DestinationIp
| where total_bytes > 5000000


### Detect Suspicious Data Transfer by Process

index=lab_logs EventID=3 ProcessName="powershell.exe"
| stats sum(BytesTransferred) as total_bytes by Host ProcessName DestinationIp
| where total_bytes > 5000000

### Detect Continuous Data Transfer Pattern

index=lab_logs EventID=3
| stats count min(_time) as firstSeen max(_time) as lastSeen by DestinationIp
| eval duration = lastSeen - firstSeen
| where count >= 5 AND duration <= 600

## Analysis
Multiple outbound connections were observed from Finance-PC to external IP 45.77.12.90.
Data transfer volume increased progressively over time.
### Key Observations:
Same destination IP
Increasing data size
Continuous outbound traffic
### Pattern Observed:
Automated data transfer
Potential staging and exfiltration
## Conclusion:
This behavior is consistent with data exfiltration, where sensitive data is being transmitted outside the network.
Combined with earlier PowerShell activity, this suggests a full compromise lifecycle.
## What Was Done
Outbound traffic to 45.77.12.90 was blocked
Affected host (Finance-PC) was isolated
Data transfer logs were reviewed for sensitive data exposure
Incident escalated for further investigation
Additional monitoring rules implemented

