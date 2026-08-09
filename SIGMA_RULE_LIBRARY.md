# Sigma Rule Library
## 10 Production-Ready Vendor-Neutral Detection Rules | MITRE ATT&CK Mapped
### By Oladapo Damilola (Wizardskull) | SOC Analyst | github.com/demonchant

---

## WHAT IS SIGMA?

Sigma is to detection rules what Snort is to network signatures.
Write ONE rule, convert it to ANY SIEM platform automatically.

Write one Sigma rule. Convert it to:
- Splunk SPL
- Microsoft Sentinel KQL
- Elastic EQL
- QRadar AQL
- Chronicle YARA-L

This is why every mature international SOC uses Sigma.

### Converting These Rules
```bash
sigmac -t splunk -c splunk-windows sigma_rule.yml
sigmac -t sentinel sigma_rule.yml
sigmac -t es-ql -c ecs-windows sigma_rule.yml
```

---

## RULE 01 — MIMIKATZ SEKURLSA MODULE
**MITRE:** T1003.001 | **Level:** critical

```yaml
title: Mimikatz sekurlsa Module Execution Detected
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
description: >
    Detects execution of Mimikatz sekurlsa module used to dump
    credentials from LSASS memory. Catches renamed Mimikatz by
    command-line arguments since sekurlsa:: must appear regardless
    of what the executable is named.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\mimikatz.exe'
            - '\mimilib.dll'
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'lsadump::'
            - 'kerberos::'
            - 'privilege::debug'
            - 'token::elevate'
            - 'lsadump::dcsync'
            - 'lsadump::sam'
    condition: selection_image OR selection_cmdline
falsepositives:
    - Authorized penetration testing
    - Red team exercises
level: critical
fields:
    - Image
    - CommandLine
    - ParentImage
    - User
    - Computer
```

### Why This Catches Renamed Mimikatz
Attackers rename mimikatz.exe to svchost.exe to bypass name-based
detection. But they cannot rename the COMMANDS — sekurlsa::logonpasswords
must always appear in the command line for Mimikatz to work.
The selection_cmdline condition catches any binary running Mimikatz commands.

---

## RULE 02 — OFFICE SPAWNING SUSPICIOUS CHILD PROCESS
**MITRE:** T1566.001 | **Level:** high

```yaml
title: Suspicious Child Process Spawned by Microsoft Office
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: production
description: >
    Detects Office applications spawning shells or scripting engines.
    Primary indicator of malicious document macro execution.
    Word.exe has zero legitimate reason to spawn cmd.exe or PowerShell.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
            - '\OUTLOOK.EXE'
            - '\ONENOTE.EXE'
            - '\MSACCESS.EXE'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\wmic.exe'
    condition: selection_parent AND selection_child
falsepositives:
    - Documented legitimate macros (add to filter)
level: high
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
    - Computer
```

---

## RULE 03 — CERTUTIL DOWNLOAD CRADLE
**MITRE:** T1105 | **Level:** high

```yaml
title: CertUtil Used as Download Cradle (LOLBas)
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: production
description: >
    Detects certutil.exe downloading files from internet URLs.
    Certutil is a Microsoft-signed certificate utility abused
    as a download cradle because security tools trust its signature.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.command_and_control
    - attack.t1105
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith: '\certutil.exe'
    selection_download:
        CommandLine|contains:
            - '-urlcache'
            - '-verifyctl'
    selection_network:
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ftp://'
    selection_decode:
        CommandLine|contains:
            - '-decode'
            - '-decodehex'
    condition: >
        selection_image AND (
            (selection_download AND selection_network)
            OR selection_decode
        )
falsepositives:
    - PKI administrators testing certificate downloads
    - Automated certificate management tools
level: high
fields:
    - Image
    - CommandLine
    - ParentImage
    - User
    - Computer
```

---

## RULE 04 — SHADOW COPY DELETION (RANSOMWARE PRECURSOR)
**MITRE:** T1490 | **Level:** critical

```yaml
title: Volume Shadow Copy Deletion - Ransomware Precursor
id: d4e5f6a7-b8c9-0123-defa-456789012345
status: production
description: >
    Detects shadow copy deletion commands used by every major
    ransomware family before encryption begins. Detection provides
    5-10 minute containment window. Covers vssadmin, wmic,
    PowerShell, wbadmin, and bcdedit methods.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'Delete Shadows'
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - 'shadowcopy delete'
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Win32_ShadowCopy'
    selection_wbadmin:
        Image|endswith: '\wbadmin.exe'
        CommandLine|contains:
            - 'delete catalog'
    selection_bcdedit:
        Image|endswith: '\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled no'
    condition: >
        selection_vssadmin OR selection_wmic OR
        selection_powershell OR selection_wbadmin OR
        selection_bcdedit
falsepositives:
    - Legitimate backup software managing shadow copies
    - System administrators manually managing disk space
level: critical
```

---

## RULE 05 — AS-REP ROASTING
**MITRE:** T1558.004 | **Level:** high

```yaml
title: AS-REP Roasting Attack Detected
id: e5f6a7b8-c9d0-1234-efab-567890123456
status: production
description: >
    Detects AS-REP Roasting where attacker requests Kerberos AS-REP
    for accounts with pre-authentication disabled. Requires ZERO
    credentials - worse than Kerberoasting. Event 4768 with RC4
    encryption from non-DC source is the signal.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.credential_access
    - attack.t1558.004
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
        TicketEncryptionType: '0x17'
        PreAuthType: '0'
    filter_dc:
        IpAddress|startswith:
            - '::1'
            - '127.'
    condition: selection AND NOT filter_dc
falsepositives:
    - Legacy systems not supporting Kerberos pre-authentication
level: high
fields:
    - TargetUserName
    - IpAddress
    - TicketEncryptionType
```

---

## RULE 06 — WMIEXEC LATERAL MOVEMENT
**MITRE:** T1047 | **Level:** high

```yaml
title: WMI Remote Code Execution for Lateral Movement
id: f6a7b8c9-d0e1-2345-fabc-678901234567
status: production
description: >
    Detects WMI being used for remote command execution via lateral
    movement. Key signal: wmiprvse.exe spawning shells or scripting
    engines, which only occurs during remote WMI execution.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral_movement
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\WmiPrvSE.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\certutil.exe'
            - '\rundll32.exe'
    filter_legitimate:
        CommandLine|contains:
            - 'C:\Windows\system32\wbem'
    condition: >
        selection_parent AND selection_child
        AND NOT filter_legitimate
falsepositives:
    - SCCM and legitimate WMI-based management software
level: high
```

---

## RULE 07 — REGISTRY RUN KEY PERSISTENCE
**MITRE:** T1547.001 | **Level:** medium

```yaml
title: Malicious Registry Run Key Persistence Created
id: a7b8c9d0-e1f2-3456-abcd-789012345678
status: production
description: >
    Detects modifications to Registry Run keys with suspicious values
    pointing to shells, interpreters, temp paths, or encoded commands.
    Legitimate software installs to Program Files and does not use
    encoded commands or internet downloads at startup.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_event
    product: windows
detection:
    selection_keys:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    selection_suspicious:
        Details|contains:
            - 'powershell'
            - 'cmd.exe'
            - 'wscript'
            - 'mshta'
            - 'rundll32'
            - '%TEMP%'
            - '%APPDATA%'
            - 'C:\Users\Public'
            - '-enc'
            - 'http://'
    filter_legitimate:
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
            - 'C:\Windows\'
    condition: >
        selection_keys AND selection_suspicious
        AND NOT filter_legitimate
falsepositives:
    - Legitimate software in non-standard paths
level: medium
```

---

## RULE 08 — PASS-THE-HASH NTLM ANOMALY
**MITRE:** T1550.002 | **Level:** high

```yaml
title: Pass-the-Hash Attack via NTLM Authentication
id: b8c9d0e1-f2a3-4567-bcde-890123456789
status: production
description: >
    Detects Pass-the-Hash by identifying NTLM network authentication
    in environments that should be using Kerberos. Workstation-to-
    workstation NTLM logons in rapid succession indicate hash-based
    lateral movement rather than legitimate authentication.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.lateral_movement
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: '3'
        AuthenticationPackageName: 'NTLM'
        LogonProcessName: 'NtLmSsp'
    filter_anonymous:
        AccountName: 'ANONYMOUS LOGON'
    filter_machine:
        AccountName|endswith: '$'
    condition: >
        selection AND NOT filter_anonymous
        AND NOT filter_machine
falsepositives:
    - Legitimate NTLM authentication to legacy file shares
    - Network printers using NTLM
level: high
```

---

## RULE 09 — POWERSHELL DOWNLOAD CRADLE
**MITRE:** T1059.001 | **Level:** high

```yaml
title: PowerShell Download Cradle Execution
id: c9d0e1f2-a3b4-5678-cdef-901234567890
status: production
description: >
    Detects PowerShell download cradles that retrieve and execute
    payloads directly in memory without writing to disk. Requires
    both a download method AND an execution method in the same
    command line — the combination that defines a download cradle.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_download:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'WebClient'
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
    selection_execute:
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - '| iex'
            - 'FromBase64String'
    condition: >
        selection_image AND
        selection_download AND
        selection_execute
falsepositives:
    - Legitimate software deployment scripts
    - Package managers using PowerShell
level: high
```

---

## RULE 10 — LSASS MEMORY ACCESS
**MITRE:** T1003.001 | **Level:** critical

```yaml
title: LSASS Memory Access by Suspicious Process
id: d0e1f2a3-b4c5-6789-defa-012345678901
status: production
description: >
    Detects non-security processes accessing LSASS memory with
    read permissions. LSASS contains credentials for all logged-in
    users. Any access from outside the security tool whitelist is
    a credential theft attempt.
author: Oladapo Damilola (@wizardskull)
date: 2024/01/01
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x40'
            - '0x1fffff'
    filter_legitimate:
        SourceImage|endswith:
            - '\MsMpEng.exe'
            - '\csrss.exe'
            - '\wininit.exe'
            - '\lsm.exe'
            - '\services.exe'
            - '\winlogon.exe'
    condition: selection AND NOT filter_legitimate
falsepositives:
    - EDR agents and security products monitoring LSASS
    - Debugging tools used by developers
level: critical
```

---

## QUICK REFERENCE

| # | Rule | MITRE | Level |
|---|---|---|---|
| 01 | Mimikatz sekurlsa Module | T1003.001 | critical |
| 02 | Office Spawning Shell | T1566.001 | high |
| 03 | CertUtil Download | T1105 | high |
| 04 | Shadow Copy Deletion | T1490 | critical |
| 05 | AS-REP Roasting | T1558.004 | high |
| 06 | WMI Lateral Movement | T1047 | high |
| 07 | Registry Run Key | T1547.001 | medium |
| 08 | Pass-the-Hash | T1550.002 | high |
| 09 | PowerShell Download | T1059.001 | high |
| 10 | LSASS Memory Access | T1003.001 | critical |

---
*SOC Analyst | Detection Engineer | github.com/demonchant*
