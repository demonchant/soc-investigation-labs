# Digital Forensics Artifact Collector & Analyser

> Processes forensic artifacts collected from a compromised Windows host — running processes, network connections, registry run keys, recently modified files, scheduled tasks, Windows Prefetch execution traces, and event log summaries. Identifies IOCs, persistence mechanisms, C2 connections, and attack tool traces for incident response investigations.

---

## Artifact Categories Analysed

| Artifact | What It Reveals |
|---|---|
| Running processes | Malicious processes, LOLBin abuse, masquerading, encoded commands |
| Network connections | Active C2 connections to known threat infrastructure |
| Registry Run keys | Persistence via auto-start entries |
| Modified files | Known malicious hashes, hidden files in suspicious paths |
| Scheduled tasks | Attacker-created persistence via task scheduler |
| Prefetch files | Execution history — proves tools ran even if deleted |
| Event log summary | Brute force volume, bulk file access patterns |

---

## Why Prefetch Is Important

Windows Prefetch files (in C:\Windows\Prefetch) record every program that has ever run on a system — including the exact timestamp and how many times. Even if an attacker deletes mimikatz.exe after running it, the Prefetch file MIMIKATZ.EXE-XXXXXXXX.pf still proves it ran. This is one of the most powerful forensic artefacts on Windows.

---

## MITRE ATT&CK Coverage

T1059, T1105, T1036.005, T1071, T1547.001, T1053.005, T1003, T1566.001, T1564.001, T1005, T1110

---

## Quick Start

```bash
python main.py
```

---

## Recommended IR Actions Generated

Every report ends with 8 specific immediate response actions tailored to the findings — from memory preservation to lateral movement review.

---

## Author

SOC L2 Analyst | github.com/demonchant
