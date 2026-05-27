# EDR Log Analyser

> Parses Windows Security Event Log and Sysmon telemetry, runs 9 MITRE ATT&CK-mapped detection modules against process, logon, registry, and file events, triages alerts by composite risk score, and groups related detections into incident chains for escalation.

---

## Architecture

```
Windows Event Log + Sysmon JSON
        |
  Event Parser  (normalise event IDs 4624/4625/4688/Sysmon 1/11/13)
        |
  EDR Detection Engine  (9 detection modules)
        |
  Triage Engine  (composite scoring + incident chain grouping)
        |
  Report Generator  (chain summary + individual alerts)
        |
  Incident Report  (console + JSON export)
```

---

## Detection Modules

| Technique | MITRE | Trigger |
|---|---|---|
| PowerShell encoded command | T1059.001 | -EncodedCommand / -Enc flag |
| Credential dumping | T1003.001 | Mimikatz, procdump, lsass process |
| Registry Run key persistence | T1547.001 | HKCU/HKLM\\...\Run key write |
| Certutil LOLBin download | T1105 | certutil -urlcache -split -f http:// |
| VSS shadow copy deletion | T1490 | vssadmin delete / wmic shadowcopy delete |
| WMIC remote execution | T1021.003 | wmic /node:x process call create |
| Office macro child spawn | T1566.001 | winword/excel → powershell/cmd |
| Password spraying | T1110.003 | Same IP → ≥3 host logon failures |
| Process masquerading | T1036.005 | svchost.exe in AppData/Temp path |

---

## Triage Scoring

Each alert receives a composite 0–100 triage score:
- Base severity: Critical +40, High +25, Medium +10, Low +3
- Critical host (DC, Exchange server): +20
- High-impact MITRE technique: +15

Alerts grouped by host into **incident chains** — if ≥3 alerts share a host, it's escalated as a confirmed **INCIDENT**.

---

## Event ID Coverage

| Event ID | Type | Source |
|---|---|---|
| 4624 | Successful Logon | Windows Security |
| 4625 | Failed Logon | Windows Security |
| 4688 | Process Creation | Windows Security |
| 4698 | Scheduled Task Created | Windows Security |
| 1 | Process Creation | Sysmon |
| 11 | File Created | Sysmon |
| 13 | Registry Value Set | Sysmon |

---

## Quick Start

```bash
python main.py
python main.py --events /path/to/edr.json --output reports/result.json
```

---

## Roadmap

- Live Windows Event Log reading (pywin32)
- EVTX binary log parsing (python-evtx)
- YARA rule scanning on dropped files
- Sigma rule format import
- Splunk / Elastic HEC export

---

## Author

SOC L2 Analyst | github.com/demonchant
