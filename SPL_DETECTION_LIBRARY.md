# Splunk SPL Detection Library
## 10 Production-Ready Detection Queries | MITRE ATT&CK Mapped
### By Oladapo Damilola (Wizardskull) | SOC Analyst | github.com/demonchant

---

## WHAT THIS LIBRARY IS

This is a collection of 10 production-ready Splunk SPL detection queries covering
the most critical attack techniques a SOC analyst encounters daily. Each query is:

- Mapped to a specific MITRE ATT&CK technique
- Tested against realistic log data
- Documented with false positive guidance
- Tunable for different environments

Every query in this library follows a consistent structure:
1. What technique it detects
2. What data source it requires
3. The SPL query itself
4. Tuning guidance
5. Response actions when it fires

---

## DETECTION 01 — KERBEROASTING DETECTION
**MITRE:** T1558.003 | **Severity:** CRITICAL | **Data Source:** Windows Security Log

### What It Detects
Kerberoasting is when an attacker requests Kerberos service tickets
encrypted with RC4 (etype 0x17) instead of AES-256, then cracks them
offline. The tell: multiple RC4 ticket requests for different service
accounts in a short window from a non-service account.

### Required Data Source
Windows Security Event Log — Event ID 4769 (Kerberos Service Ticket Request)
forwarded from Domain Controllers to Splunk.

### The SPL Query

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4769
Ticket_Encryption_Type=0x17
NOT Account_Name="*$"
NOT Service_Name IN ("krbtgt", "kadmin")
| bucket _time span=5m
| stats
    count as total_requests
    dc(Service_Name) as unique_spns
    values(Service_Name) as spn_list
    values(Client_Address) as source_ips
    by Account_Name, _time
| where unique_spns >= 3
| eval risk_score=case(
    unique_spns >= 10, "CRITICAL",
    unique_spns >= 5,  "HIGH",
    unique_spns >= 3,  "MEDIUM"
  )
| eval mitre_technique="T1558.003 - Kerberoasting"
| table _time Account_Name unique_spns spn_list source_ips risk_score mitre_technique
| sort - unique_spns
```

### Query Breakdown — Line by Line

`EventCode=4769` — Kerberos Service Ticket Request events only.

`Ticket_Encryption_Type=0x17` — RC4 encryption. This is the attacker's
choice because RC4 is crackable offline in hours. AES-256 (0x12, 0x11)
is the legitimate modern standard.

`NOT Account_Name="*$"` — Exclude computer accounts (they end with $).
Domain Controllers legitimately make RC4 requests. This removes them.

`dc(Service_Name) as unique_spns` — Count distinct service accounts targeted.
Legitimate users request 1-2 service tickets. Kerberoasting tools request 20-50.

`where unique_spns >= 3` — Three or more unique SPNs in 5 minutes from one
account = suspicious. Tune this threshold based on your environment.

### False Positive Sources
- Legacy applications that require RC4 (very old software)
- Some backup solutions request multiple service tickets
- Penetration testers running authorized assessments

### Tuning Guidance
```spl
| where unique_spns >= 3
NOT Account_Name IN ("svc_legacy_app", "backup_agent")
```

Add known-legitimate RC4 users to the NOT IN list with documented justification.

### Response When This Fires
1. Identify the account — is it a service account or user account?
2. Check the workstation the request came from
3. Review what SPNs were targeted — are they high-privilege service accounts?
4. Force password reset on targeted service accounts
5. Investigate the source machine for compromise

---

## DETECTION 02 — PASSWORD SPRAY DETECTION
**MITRE:** T1110.003 | **Severity:** HIGH | **Data Source:** Windows Security Log

### What It Detects
Password spray is when an attacker tries one common password against
many accounts — staying deliberately under the per-account lockout
threshold. The pattern: one source, many accounts, few attempts per account.

### The SPL Query

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
Logon_Type IN ("3", "8", "10")
| bucket _time span=10m
| stats
    count as total_failures
    dc(Account_Name) as unique_accounts
    values(Account_Name) as targeted_accounts
    values(Failure_Reason) as failure_reasons
    by IpAddress, _time
| where unique_accounts >= 10 AND total_failures >= 10
| eval attempts_per_account=round(total_failures/unique_accounts, 2)
| where attempts_per_account <= 3
| eval spray_confidence=case(
    unique_accounts >= 50, "CRITICAL - Active Spray Campaign",
    unique_accounts >= 20, "HIGH - Likely Spray",
    unique_accounts >= 10, "MEDIUM - Possible Spray"
  )
| eval mitre_technique="T1110.003 - Password Spraying"
| table _time IpAddress total_failures unique_accounts
         attempts_per_account targeted_accounts spray_confidence mitre_technique
| sort - unique_accounts
```

### Why attempts_per_account <= 3 Matters
This is the lockout evasion signal. The attacker knows your lockout
threshold is probably 5. They deliberately try 2-3 attempts per account
and move on. High unique account count + low attempts per account =
deliberate lockout evasion.

### False Positive Sources
- Mass account migrations (IT creating many accounts and testing logins)
- Vulnerability scanners with credential testing enabled
- Users fat-fingering passwords across many systems simultaneously

### Response When This Fires
1. Block the source IP at the perimeter immediately
2. Check if any account succeeded — Event 4624 from same IP = compromise
3. Notify affected users to change passwords
4. Review IP reputation against threat intelligence feeds

---

## DETECTION 03 — ENCODED POWERSHELL EXECUTION
**MITRE:** T1059.001 | **Severity:** HIGH | **Data Source:** Sysmon Event 1

### What It Detects
Attackers encode PowerShell commands in Base64 to hide their intent
from casual log inspection. The -enc or -EncodedCommand flag is the
tell. Combined with hidden window and no-profile flags = attack signature.

### The SPL Query

```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=1
Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
 OR CommandLine="*-ec *")
| eval suspicious_flags=mvfind(
    split(lower(CommandLine), " "),
    "(-nop|-noprofile|-w\s+hid|-windowstyle\s+hid|-noninteractive|-noni)"
  )
| eval parent_suspicious=case(
    match(ParentImage, "(?i)(WINWORD|EXCEL|OUTLOOK|POWERPNT|mshta|wscript|cscript)"),
    "MALICIOUS_PARENT - Document executing PowerShell",
    match(ParentImage, "(?i)(cmd\.exe|powershell\.exe)"),
    "SUSPICIOUS_PARENT - Shell spawning shell",
    true(), "NORMAL_PARENT"
  )
| eval base64_length=len(replace(CommandLine,
    ".*(?:-enc|-EncodedCommand|-ec)\s+([A-Za-z0-9+/=]+).*", "\1"))
| eval risk=case(
    parent_suspicious="MALICIOUS_PARENT - Document executing PowerShell",
    "CRITICAL",
    isnotnull(suspicious_flags) AND parent_suspicious!="NORMAL_PARENT",
    "HIGH",
    isnotnull(suspicious_flags),
    "MEDIUM",
    true(), "LOW"
  )
| where risk IN ("CRITICAL", "HIGH", "MEDIUM")
| table _time Computer User Image ParentImage CommandLine
         parent_suspicious risk
| sort - risk
```

### The Parent Process Is Everything
The most important field here is ParentImage. PowerShell spawned by:
- WINWORD.EXE = malicious document macro (CRITICAL)
- EXCEL.EXE = malicious spreadsheet macro (CRITICAL)
- OUTLOOK.EXE = phishing email attachment (CRITICAL)
- cmd.exe = command execution chain (HIGH)
- explorer.exe = user ran it directly (investigate)
- svchost.exe = service or scheduled task (investigate)

### Response When This Fires
1. Decode the Base64 immediately — use CyberChef or Python
2. The decoded content tells you the attacker's exact intent
3. Pull Sysmon Event 3 — did PowerShell make outbound connections?
4. Pull Sysmon Event 10 — did PowerShell access LSASS?
5. Isolate the machine if C2 connections or LSASS access is confirmed

---

## DETECTION 04 — LSASS CREDENTIAL DUMPING
**MITRE:** T1003.001 | **Severity:** CRITICAL | **Data Source:** Sysmon Event 10

### What It Detects
LSASS (Local Security Authority Subsystem Service) holds authentication
credentials in memory. Mimikatz and similar tools open LSASS with
memory read access to extract hashes and tickets. Sysmon Event 10
captures this exact moment.

### The SPL Query

```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=10
TargetImage="*\\lsass.exe"
| eval granted_access_int=tonumber(GrantedAccess, 16)
| eval is_read_access=if(
    (granted_access_int BAND 0x10) > 0 OR
    (granted_access_int BAND 0x20) > 0 OR
    (granted_access_int BAND 0x400) > 0,
    "YES", "NO"
  )
| where is_read_access="YES"
NOT SourceImage IN (
    "*\\MsMpEng.exe",
    "*\\SenseCnfg.exe",
    "*\\csrss.exe",
    "*\\wininit.exe",
    "*\\winlogon.exe",
    "*\\lsm.exe",
    "*\\services.exe",
    "*\\svchost.exe",
    "*\\taskhost.exe"
  )
| eval tool_signature=case(
    match(SourceImage, "(?i)(procdump|mimikatz|wce|pwdump|fgdump)"),
    "KNOWN_CREDENTIAL_TOOL",
    match(SourceImage, "(?i)(powershell|cmd|rundll32|regsvr32)"),
    "SUSPICIOUS_SHELL",
    match(SourceImage, "(?i)(python|ruby|perl|java)"),
    "SCRIPTING_ENGINE",
    true(), "UNKNOWN_PROCESS"
  )
| eval severity=case(
    tool_signature="KNOWN_CREDENTIAL_TOOL", "CRITICAL",
    tool_signature="SUSPICIOUS_SHELL", "CRITICAL",
    tool_signature="SCRIPTING_ENGINE", "HIGH",
    true(), "HIGH"
  )
| eval mitre_technique="T1003.001 - LSASS Memory"
| table _time Computer User SourceImage TargetImage
         GrantedAccess tool_signature severity mitre_technique
| sort - severity
```

### The Access Flags Explained
0x10 = PROCESS_VM_READ — read process memory (Mimikatz needs this)
0x20 = PROCESS_VM_WRITE — write to process memory
0x400 = PROCESS_QUERY_INFORMATION — query process info

Any process reading LSASS memory that isn't a whitelisted security tool
is almost certainly attempting credential theft.

### Response When This Fires
1. Treat all credentials on this machine as compromised IMMEDIATELY
2. Force password reset for every account with an active session
3. Check Event 4624 for any unusual authentications AFTER this event
4. Check for lateral movement from this machine
5. Investigate what deployed the credential dumping tool

---

## DETECTION 05 — LATERAL MOVEMENT VIA PSEXEC
**MITRE:** T1569.002 | **Severity:** HIGH | **Data Source:** Windows Security + Sysmon

### What It Detects
PsExec creates a service (PSEXESVC) on the remote machine to execute
commands. This service creation leaves a distinctive artifact in the
Windows System log. Combined with network authentication events,
this detection catches PsExec-based lateral movement.

### The SPL Query

```spl
index=wineventlog
(sourcetype=WinEventLog:System EventCode=7045
 Service_Name IN ("PSEXESVC", "psexesvc")
 NOT Image_Path IN ("*\\PsExec*", "*\\psexec*"))
OR
(sourcetype=WinEventLog:Security EventCode=4624
 Logon_Type="3"
 Account_Name!="ANONYMOUS LOGON"
 AuthenticationPackageName="NTLM")
| eval event_type=case(
    EventCode="7045", "SERVICE_CREATED",
    EventCode="4624", "NETWORK_LOGON",
    true(), "OTHER"
  )
| eval source_machine=coalesce(IpAddress, WorkstationName, Computer)
| stats
    values(event_type) as event_types
    values(Account_Name) as accounts_used
    values(Service_Name) as services
    count by source_machine, Computer, _time span=5m
| where mvcount(event_types) > 1
| eval lateral_movement_confidence=case(
    mvfind(event_types, "SERVICE_CREATED") >= 0
    AND mvfind(event_types, "NETWORK_LOGON") >= 0,
    "HIGH - PsExec lateral movement confirmed",
    mvfind(event_types, "SERVICE_CREATED") >= 0,
    "MEDIUM - Service creation only",
    true(), "LOW"
  )
| eval mitre_technique="T1569.002 - Service Execution (PsExec)"
| table _time source_machine Computer accounts_used services
         lateral_movement_confidence mitre_technique
```

### Why Correlate Two Event Types?
PSEXESVC service creation alone could be legitimate IT admin work.
NTLM network logon alone is normal. But PSEXESVC service creation
AND NTLM logon from the same source to the same destination in the
same 5-minute window is highly specific to PsExec usage.

### Response When This Fires
1. Verify: is this an authorized IT admin action? Check the account.
2. If unauthorized: isolate both source and destination machines
3. Check what commands were run via the PSEXESVC service
4. Look for additional lateral movement from the destination machine

---

## DETECTION 06 — DNS EXFILTRATION DETECTION
**MITRE:** T1048.001 | **Severity:** HIGH | **Data Source:** DNS Server Logs

### What It Detects
DNS tunnelling encodes stolen data in subdomain labels. Normal subdomains
are human-readable words with low entropy. Encoded data has high entropy
— it looks random because it IS random-looking encoded bytes.

### The SPL Query

```spl
index=dns sourcetype=dns_logs
| rex field=query "^(?P<subdomain>[^.]+)\.(?P<apex_domain>[^.]+\.[^.]+)$"
| where isnotnull(subdomain)
| eval subdomain_length=len(subdomain)
| eval char_counts=split(lower(subdomain), "")
| eval unique_chars=mvcount(mvdedup(char_counts))
| eval entropy=-(
    (mvcount(mvfilter(match(char_counts, "a")))/subdomain_length
     * log(mvcount(mvfilter(match(char_counts, "a")))/subdomain_length, 2))
  )
| eval high_entropy=if(subdomain_length > 20 AND unique_chars > 12, "YES", "NO")
| where high_entropy="YES"
| stats
    count as query_count
    dc(subdomain) as unique_subdomains
    values(src_ip) as source_ips
    dc(src_ip) as unique_sources
    by apex_domain
| where unique_subdomains >= 15
| eval exfil_likelihood=case(
    unique_subdomains >= 50, "CRITICAL",
    unique_subdomains >= 25, "HIGH",
    unique_subdomains >= 15, "MEDIUM"
  )
| eval mitre_technique="T1048.001 - Exfiltration Over DNS"
| table apex_domain query_count unique_subdomains
         source_ips exfil_likelihood mitre_technique
| sort - unique_subdomains
```

### Why Unique Subdomains Is the Key Signal
Every DNS tunnelling query carries a different chunk of data, so each
query has a different subdomain. A legitimate CDN might use long
subdomains — but it uses the SAME ones repeatedly. DNS tunnelling
generates hundreds of UNIQUE high-entropy subdomains for one apex domain.

### False Positive Sources
- Some CDNs use long random-looking subdomains (Akamai, CloudFront)
- Legitimate DGA (Domain Generation Algorithm) traffic from malware
  that's not tunnelling but generating random domains

### Tuning
```spl
NOT apex_domain IN (
    "akadns.net", "cloudfront.net", "akamaiedge.net",
    "cloudflare.net", "fastly.net"
  )
```

---

## DETECTION 07 — DCSync ATTACK DETECTION
**MITRE:** T1003.006 | **Severity:** CRITICAL | **Data Source:** Windows Security Log

### What It Detects
DCSync exploits Active Directory replication rights. An attacker with
DS-Replication-Get-Changes rights can pretend to be a Domain Controller
and request all password hashes. Event 4662 on the DC captures this
replication request from non-DC accounts.

### The SPL Query

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
Object_Type="domainDNS"
(Properties="*1131f70a*" OR Properties="*1131f70f*"
 OR Properties="*89e95b76*")
| eval replication_right=case(
    match(Properties, "1131f70a"),
    "DS-Replication-Get-Changes",
    match(Properties, "1131f70f"),
    "DS-Replication-Get-Changes-All",
    match(Properties, "89e95b76"),
    "DS-Replication-Get-Changes-In-Filtered-Set",
    true(), "Unknown-Replication-Right"
  )
| eval is_domain_controller=if(
    match(Account_Name, ".*\$$"),
    "YES", "NO"
  )
| where is_domain_controller="NO"
| eval severity="CRITICAL"
| eval alert_message="Non-DC account exercised AD replication rights. "
    ."This is the DCSync attack signature. Account: " + Account_Name
    +" | Right Used: " + replication_right
| eval mitre_technique="T1003.006 - DCSync"
| table _time Computer Account_Name replication_right
         severity alert_message mitre_technique
| sort _time
```

### The GUIDs Explained
1131f70a = DS-Replication-Get-Changes
1131f70f = DS-Replication-Get-Changes-All
89e95b76 = DS-Replication-Get-Changes-In-Filtered-Set

All three appear in Event 4662 Properties field when a replication
request is made. Only Domain Controllers should trigger these.
Any other account = DCSync attack in progress.

### Response — This Is Your Fastest Response Required
1. This alert means all domain password hashes may be compromised
2. Rotate KRBTGT password TWICE (10 hours apart minimum)
3. Force password reset for ALL privileged accounts IMMEDIATELY
4. Identify the account that triggered this and how it was compromised
5. Assume Golden Ticket capability — monitor for forged ticket usage

---

## DETECTION 08 — SUSPICIOUS SCHEDULED TASK CREATION
**MITRE:** T1053.005 | **Severity:** HIGH | **Data Source:** Windows Security Log

### What It Detects
Attackers create scheduled tasks for persistence — they survive reboots
and run automatically. Event 4698 captures new task creation. The key
signals: tasks pointing to suspicious paths, tasks running as SYSTEM,
tasks created outside business hours.

### The SPL Query

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4698
| rex field=_raw "TaskName>\s*(?P<task_name>[^<]+)"
| rex field=_raw "Command>\s*(?P<task_command>[^<]+)"
| rex field=_raw "UserId>\s*(?P<run_as_user>[^<]+)"
| eval hour_of_day=strftime(_time, "%H")
| eval day_of_week=strftime(_time, "%A")
| eval outside_hours=if(
    hour_of_day < "08" OR hour_of_day > "18"
    OR day_of_week IN ("Saturday", "Sunday"),
    "YES", "NO"
  )
| eval suspicious_path=case(
    match(task_command, "(?i)(\\\\temp\\\\|\\\\tmp\\\\|appdata\\\\|programdata\\\\)"),
    "TEMP_PATH",
    match(task_command, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)"),
    "INTERPRETER",
    match(task_command, "(?i)(-enc|-encodedcommand|-e )"),
    "ENCODED_COMMAND",
    match(task_command, "(?i)(http://|https://|ftp://)"),
    "NETWORK_URL",
    true(), "NORMAL_PATH"
  )
| eval system_task=if(run_as_user="S-1-5-18" OR run_as_user="NT AUTHORITY\\SYSTEM",
    "YES", "NO")
| eval risk_score=0
| eval risk_score=risk_score + if(outside_hours="YES", 30, 0)
| eval risk_score=risk_score + if(suspicious_path!="NORMAL_PATH", 40, 0)
| eval risk_score=risk_score + if(system_task="YES", 20, 0)
| eval severity=case(
    risk_score >= 70, "CRITICAL",
    risk_score >= 40, "HIGH",
    risk_score >= 20, "MEDIUM",
    true(), "LOW"
  )
| where severity IN ("CRITICAL", "HIGH", "MEDIUM")
| table _time Computer SubjectUserName task_name task_command
         run_as_user outside_hours suspicious_path severity
| sort - risk_score
```

### Risk Scoring Logic
- Created outside business hours: +30 (attacker's timezone)
- Points to temp/interpreter/encoded/URL: +40 (malicious path pattern)
- Runs as SYSTEM: +20 (maximum privilege persistence)

Score 70+ = CRITICAL. Score 40+ = HIGH. Score 20+ = MEDIUM.

---

## DETECTION 09 — BEACONING DETECTION VIA FIREWALL LOGS
**MITRE:** T1071.001 | **Severity:** HIGH | **Data Source:** Firewall/Proxy Logs

### What It Detects
C2 beaconing is regular, machine-like communication to an attacker's
server. Humans browse irregularly. Malware checks in at predictable
intervals with low variance. This query measures that variance using
coefficient of variation on connection intervals.

### The SPL Query

```spl
index=firewall sourcetype=firewall_logs
action=allowed dest_port IN ("80", "443", "8080", "8443", "4444", "1337")
NOT dest_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| sort src_ip dest_ip _time
| streamstats
    current=f
    last(_time) as prev_time
    by src_ip dest_ip
| eval interval_seconds=_time - prev_time
| where interval_seconds > 0 AND interval_seconds < 7200
| stats
    count as connection_count
    avg(interval_seconds) as avg_interval
    stdev(interval_seconds) as stdev_interval
    min(interval_seconds) as min_interval
    max(interval_seconds) as max_interval
    values(dest_port) as ports_used
    by src_ip dest_ip
| where connection_count >= 10
| eval cv=round(stdev_interval/avg_interval, 4)
| eval avg_interval_min=round(avg_interval/60, 2)
| eval beaconing_likelihood=case(
    cv <= 0.10, "CRITICAL - Almost certainly beaconing",
    cv <= 0.20, "HIGH - Strong beaconing signal",
    cv <= 0.35, "MEDIUM - Possible beaconing",
    true(), "LOW - Irregular traffic"
  )
| where cv <= 0.35
| eval mitre_technique="T1071.001 - Web Protocols C2"
| table src_ip dest_ip connection_count avg_interval_min
         cv beaconing_likelihood ports_used mitre_technique
| sort cv
```

### The CV Math
CV = Standard Deviation / Mean

CV near 0 = perfectly regular (robot-like)
CV near 1+ = highly irregular (human-like)

Real human browsing: CV 0.8 to 2.0
C2 beacon with 15% jitter: CV 0.08 to 0.15
Your threshold: flag anything below 0.35

### Response When This Fires
1. Check the destination IP against threat intel feeds
2. Identify the process making the connection (endpoint logs)
3. Look at data volume — large outbound = possible exfiltration
4. If C2 confirmed: isolate the machine, block the IP

---

## DETECTION 10 — IMPOSSIBLE TRAVEL DETECTION
**MITRE:** T1078 | **Severity:** HIGH | **Data Source:** Authentication/VPN Logs

### What It Detects
A user's account logs in from Lagos at 10:00 AM. Thirty minutes later,
the same account logs in from London. Lagos to London = 5,000km.
Commercial flight = 6+ hours. The second login is not the real user.

### The SPL Query

```spl
index=auth sourcetype=auth_logs action=success
| iplocation src_ip
| eval location=City + ", " + Country
| sort Account_Name _time
| streamstats
    current=f
    last(_time) as prev_time
    last(lat) as prev_lat
    last(lon) as prev_lon
    last(location) as prev_location
    last(src_ip) as prev_ip
    by Account_Name
| where isnotnull(prev_lat) AND isnotnull(prev_lon)
| eval time_diff_hours=((_time - prev_time) / 3600)
| eval lat1=lat * pi() / 180
| eval lat2=prev_lat * pi() / 180
| eval dlat=(prev_lat - lat) * pi() / 180
| eval dlon=(prev_lon - lon) * pi() / 180
| eval a=sin(dlat/2) * sin(dlat/2)
       + cos(lat1) * cos(lat2) * sin(dlon/2) * sin(dlon/2)
| eval c=2 * atan2(sqrt(a), sqrt(1-a))
| eval distance_km=round(6371 * c, 0)
| eval required_speed_kmh=round(distance_km / time_diff_hours, 0)
| where distance_km > 100 AND time_diff_hours < 6
| eval travel_possible=if(required_speed_kmh > 900, "IMPOSSIBLE", "SUSPICIOUS")
| eval severity=case(
    required_speed_kmh > 5000, "CRITICAL",
    required_speed_kmh > 900,  "HIGH",
    required_speed_kmh > 500,  "MEDIUM",
    true(), "LOW"
  )
| where travel_possible="IMPOSSIBLE"
| eval mitre_technique="T1078 - Valid Accounts (Impossible Travel)"
| table _time Account_Name src_ip prev_ip location prev_location
         distance_km time_diff_hours required_speed_kmh
         travel_possible severity mitre_technique
| sort - required_speed_kmh
```

### The Haversine Formula in SPL
The a/c/distance_km calculation is the Haversine formula — it computes
great-circle distance between two GPS coordinates on a sphere (Earth).
This is the same formula Google Maps uses for distance calculation.

Required speed = distance / time. If speed > 900 km/h (commercial
aircraft top speed), the travel is physically impossible.

### False Positive Sources
- Corporate VPN users (their IP appears to be in a different country)
- Users who share credentials (bad security practice, common reality)
- Proxy services or cloud desktops

### Tuning
```spl
NOT src_ip IN ("corporate_vpn_ip_1", "corporate_vpn_ip_2")
NOT Account_Name IN ("service_accounts", "api_accounts")
```

---

## HOW TO USE THIS LIBRARY

### Deployment Checklist
Before deploying any query to production:

1. **Test against historical data** — run against 30 days of logs
   and manually review every result. Know your baseline FP rate.

2. **Add environment-specific exclusions** — every environment has
   legitimate processes that look suspicious. Document and exclude them.

3. **Set appropriate time windows** — the bucket span in each query
   is a starting point. Adjust based on your log volume and alert
   expectations.

4. **Connect to SOAR** — each query should trigger an automated
   response playbook for the first containment actions.

5. **Review monthly** — attacker techniques evolve. Review each
   detection quarterly and update based on new threat intelligence.

### Quick Reference Table

| # | Detection | MITRE | Severity | Data Source |
|---|---|---|---|---|
| 01 | Kerberoasting | T1558.003 | CRITICAL | WinSec 4769 |
| 02 | Password Spray | T1110.003 | HIGH | WinSec 4625 |
| 03 | Encoded PowerShell | T1059.001 | HIGH | Sysmon 1 |
| 04 | LSASS Dumping | T1003.001 | CRITICAL | Sysmon 10 |
| 05 | PsExec Lateral Movement | T1569.002 | HIGH | WinSec + Sysmon |
| 06 | DNS Exfiltration | T1048.001 | HIGH | DNS Logs |
| 07 | DCSync | T1003.006 | CRITICAL | WinSec 4662 |
| 08 | Malicious Scheduled Task | T1053.005 | HIGH | WinSec 4698 |
| 09 | C2 Beaconing | T1071.001 | HIGH | Firewall Logs |
| 10 | Impossible Travel | T1078 | HIGH | Auth Logs |

---

*SOC Analyst | Detection Engineer | github.com/demonchant*
