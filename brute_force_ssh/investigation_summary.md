Incident Title:Suspected SSH Brute Force Attack on Linux Server

Date Detected:February 6, 2026

Data Source:Linux authentication logs

Sourcetype: sshd

Incident Description:Multiple failed SSH login attempts were detected on a Linux server targeting the root account from a single external IP address. 
The repeated failures followed by a successful login suggest a possible brute force attack.

Evidence (Log Extracts)
Feb 06 03:12:41 Failed password for root from 185.199.110.27
Feb 06 03:12:44 Failed password for root from 185.199.110.27
Feb 06 03:12:47 Failed password for root from 185.199.110.27
Feb 06 03:12:50 Failed password for root from 185.199.110.27
Feb 06 03:13:02 Accepted password for root from 185.199.110.27

Indicators of Compromise (IOCs)

IP Address: 185.199.110.27
Targeted Account: root
Attack Type: SSH Brute Force

Impact Assessment:
The attacker successfully authenticated as the root user, potentially gaining full administrative access to the system.

Response Actions:
Blocked the source IP address
Forced password reset for the root account
Disabled root SSH login
Enabled SSH key-based authentication

Recommendations:
Implement fail2ban
Monitor repeated authentication failures
Enforce strong password policies

Enable alerting for brute force pattern in Splunk
