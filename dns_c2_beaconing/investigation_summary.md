Scenario Title:Suspected DNS-Based Command and Control (C2) Beaconing

Situation:SOC receives an alert that a user workstation may be communicating with a malicious external server using DNS and HTTPS.

DNS LOGS:
Timestamp: 2026-01-22 14:03:11
Source_IP: 10.10.5.23
Query_Name: j29sk2l0d.attacker-domain.com
Query_Type: A
Response_IP: 185.231.72.19
TTL: 60

Repeated entries every 5 minutes:
Timestamp: 2026-01-22 14:08:11
Timestamp: 2026-01-22 14:13:11
Timestamp: 2026-01-22 14:18:11

FIREWALL LOGS:
Timestamp: 2026-01-22 14:03:13
Source_IP: 10.10.5.23
Destination_IP: 185.231.72.19
Destination_Port: 443
Protocol: TCP
Action: ALLOW

PROXY LOGS:
Timestamp: 2026-01-22 14:03:14
Source_IP: 10.10.5.23
URL: https://j29sk2l0d.attacker-domain.com/api/checkin
HTTP_Method: POST
Bytes_Sent: 1380
Bytes_Received: 520
User_Agent: Mozilla/5.0

ENDPOINT :
Hostname: USER-PC-023
User: finance.user
OS: Windows 10
Role: Non-technical user

INVESTIGATION SUMMARY:DNS-Based C2 Beaconing
1. Incident Overview

On 2026-01-22, a Windows workstation (USER-PC-023) was observed making repeated DNS queries and outbound HTTPS connections to a suspicious external domain. 
The activity originated from internal IP address 10.10.5.23 and occurred at consistent time intervals.
2. Detection Source

The activity was detected through analysis of DNS logs, firewall logs, and proxy logs ingested into the SIEM. 
The alert was triggered due to repeated DNS queries to a randomized domain followed by outbound HTTPS traffic.
3. Investigation Steps

Reviewed DNS logs for abnormal query patterns
Identified repeated queries to a randomized subdomain
Correlated DNS activity with firewall logs to confirm outbound connections
Reviewed proxy logs to analyze HTTP methods and traffic behavior
Evaluated endpoint context to determine expected behavior
4. Evidence Observed

DNS queries contained randomized subdomains, consistent with algorithm-generated domains
Low DNS Time To Live (TTL) value of 60 seconds
Outbound TCP connections to destination port 443
Repeated POST requests to the same external endpoint
Connections occurred at 5-minute intervals, consistent with beaconing behavior
User-Agent string appeared generic and potentially spoofed
5. Impact Assessment

The affected system was identified as a user workstation. No evidence of lateral movement or large-scale data exfiltration was observed during the investigation window.
6. Response Actions

The affected endpoint was isolated from the network
The suspicious domain and IP address were blocked
User credentials were reset as a precautionary measure
Incident was escalated to Tier 2 for further malware analysis
7. Final Assessment

Based on observed behavior and log correlation, the activity was assessed as High Confidence Malware Infection involving Command-and-Control (C2) communication.
On 2026-01-22, a Windows workstation (USER-PC-023) was observed making repeated DNS queries and outbound HTTPS connections to a suspicious external domain. The activity originated from internal IP address 10.10.5.23 and occurred at consistent time intervals.
