On 02/10/2026, a firewall alert was triggered when an internal host attempted to access an external URL listed on the organization's blacklist.
The outbound connection was blocked successfully. The URL was a shortened link commonly associated with phishing and malware delivery campaigns.
Although no connection was established, the event required investigation due to its high-risk classification.

Data Source: Firewall
Timestamp: 02/10/2026 21:56:54.878
Action: Blocked
Source IP: 10.20.2.17
Source Port: 34257
Destination IP: 67.199.248.11
Destination Port: 80
URL: http://bit.ly/3sHkX3da12340
Application: Web-browsing
Protocol: TCP
Severity: High

The requested URL is a shortened link (bit.ly), which is commonly abused in phishing and malware campaigns to obscure the final destination.
The domain was flagged by threat intelligence feeds, indicating known malicious activity.
Although the firewall successfully blocked the request, the attempt suggests that the user may have clicked a malicious link or that malware attempted outbound communication.

Indicators of Compromise:
Malicious URL: http://bit.ly/3sHkX3da12340
Destination IP: 67.199.248.11
Unusual outbound HTTP request to known blacklisted domain

Ivestigation:
Verified the URL against threat intelligence and blacklist sources.
Confirmed the firewall blocked the outbound request.
Identified the source host as an internal endpoint.
Assessed the risk of phishing or malware exposure based on URL characteristics.

Determination:
This alert was classified as a True Positive.  
Although the connection was blocked, the attempted access to a known malicious URL represents a genuine security concern and potential precursor to compromise.
No confirmed impact was observed. The outbound connection was blocked, preventing communication with the malicious destination. 
No evidence of data exfiltration or successful compromise was identified at this stage.

Recommended Actions:
Notify the affected user and assess recent email or web activity.
Scan the endpoint for malware or suspicious processes.
Review DNS and proxy logs for additional attempts to reach malicious domains.
Reinforce user phishing awareness training.
Escalation:
The alert was escalated to Tier 2 SOC for further endpoint investigation due to the high-risk nature of the malicious URL and potential phishing exposure.

Final statement:
This investigation highlights the importance of monitoring blocked events,
as attempted connections to malicious infrastructure can indicate early attack stages even when preventive controls are effective.



