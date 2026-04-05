# SOC Monitoring Dashboard Lab (Splunk Visualization & Alerting)

## Scenario

A Security Operations Center (SOC) requires a centralized dashboard to monitor ongoing threats in real time.

This lab simulates the design of a SOC dashboard in Splunk to track critical security events, including PowerShell activity, failed logins, network connections, and lateral movement.


## Objective

Build a monitoring dashboard that provides visibility into:

- Suspicious PowerShell execution  
- Network beaconing activity  
- Failed login attempts  
- Lateral movement indicators  


## Dashboard Panels

### Panel 1 — PowerShell Activity

```spl
index=lab_logs EventID=4688 ProcessName="powershell.exe"
| stats count by Host
| sort -count

Purpose:

Identify hosts running PowerShell frequently
Panel 2 — Failed Login Attempts

### index=lab_logs EventID=4625

| stats count by Host Account_Name
| sort -count

Purpose:

Detect brute force or password spraying attempts

### Panel 3 — Network Connections

index=lab_logs EventID=3
| stats count by DestinationIp
| sort -count

Purpose:

Identify most contacted external IPs

### Panel 4 — Beaconing Detection

index=lab_logs EventID=3 ProcessName="powershell.exe"
| stats count min(_time) as firstSeen max(_time) as lastSeen by DestinationIp
| eval duration = lastSeen - firstSeen
| where count >= 5 AND duration <= 600

Purpose:

Detect automated command-and-control communication

### Panel 5 — Lateral Movement

index=lab_logs EventID=4688 ProcessName="powershell.exe"
| search ParentProcessName IN ("wmiprvse.exe","psexec.exe","services.exe")
| stats count by Host ParentProcessName

Purpose:

Detect remote execution and lateral movement

## Visualization

Each panel can be configured as:

Bar Chart (Top hosts / IPs)
Table View (Detailed logs)
Time Chart (Activity over time)
Alert Integration

Each panel can be converted into alerts:

Trigger when thresholds exceeded
Example:

5 failed logins → alert

Beaconing detected → high severity alert

## Analysis

Dashboard provides real-time visibility into security events
Combines multiple detection strategies into one interface
Key Insight:
Centralized monitoring improves detection speed
Reduces manual investigation time

## What Was Done

Designed multiple monitoring panels
Integrated detection queries into dashboard
Configured alert thresholds
Structured dashboard for SOC workflow
