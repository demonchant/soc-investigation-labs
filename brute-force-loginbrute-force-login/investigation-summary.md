Scenario:A SOC alert triggers after multiple failed login attempts against a Windows system. The concern is credential stuffing or brute force from an external source.

WINDOWS SECURITY LOGS
Failed login events (Event ID 4625)
Time: 2026-01-24 01:12:03
EventCode: 4625
User: admin
Source_IP: 103.45.77.18
Logon_Type: 3
Status: Failure

Time: 2026-01-24 01:12:06
EventCode: 4625
User: administrator
Source_IP: 103.45.77.18
Logon_Type: 3
Status: Failure

Time: 2026-01-24 01:12:09
EventCode: 4625
User: finance.user
Source_IP: 103.45.77.18
Logon_Type: 3
Status: Failure


This pattern repeats 52 times in 3 minutes.

SUCCESSFUL LOGIN CHECK (Event ID 4624)
SOC checks for success after failures:

Time: 2026-01-24 01:20:11
EventCode: 4624
User: finance.user
Source_IP: 10.10.5.41
Logon_Type: 2
Status: Success


Important detail:

Different IP
Internal address
Normal user activity

SYSTEM CONTEXT

Hostname: HR-LAPTOP-014
User role: HR staff
OS: Windows 10
Exposed to internet: No (attempt via VPN gateway)

INVESTIGATION SUMMARY 
Investigation Summary: Brute Force Login Attempt
1. Incident Overview

On 2026-01-24, multiple failed login attempts were observed targeting a Windows workstation (HR-LAPTOP-014).
The activity originated from a single external IP address and targeted multiple user accounts within a short time frame.

2. Detection Source

The activity was detected through Windows Security Event logs ingested into the SIEM.
The alert was triggered based on a high volume of Event ID 4625 (Failed Logon) events.

3. Investigation Steps

Reviewed Windows authentication logs for failed login events
Filtered events within a short time window
Grouped failed attempts by source IP and username
Checked for any successful login events following the failures
Reviewed system context to determine expected behavior

4. Evidence Observed

52 failed login attempts within approximately 3 minutes
All attempts originated from the same external IP address (103.45.77.18)
Multiple common usernames were targeted, including admin and administrator
Logon Type 3 indicated network-based authentication attempts
No successful login events were associated with the source IP

5. Impact Assessment

No unauthorized access was identified. All login attempts from the suspicious IP address were unsuccessful, and no account compromise was confirmed.

6. Response Actions

Source IP address was blocked at the perimeter firewall
Targeted user accounts were monitored for additional activity
Alert severity was classified as Medium
Incident documented for trend analysis

7. Final Assessment

Based on observed behavior and log analysis, the activity was assessed as a brute force login attempt with no confirmed compromise.
