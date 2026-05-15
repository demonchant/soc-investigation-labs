# SOC Automation Engine

> A production-style Security Operations Center (SOC) automation pipeline that ingests logs, normalizes events, applies MITRE ATT&CK-mapped detection rules, and generates structured incident reports.

---

## Architecture

```
Raw Logs (JSON)
      |
  Log Parser (normalize + validate)
      |
  Rule Loader (YAML-based ruleset)
      |
  Detection Engine (multi-rule handler dispatch)
      |
  Report Generator (severity-classified output)
      |
  Incident Report (console + JSON export)
```

---

## Features

| Feature | Details |
|---|---|
| Log normalization | Validates required fields, handles malformed entries gracefully |
| YAML rule engine | Human-readable, extensible detection rules |
| Brute force detection | MITRE T1110 — threshold-based, per source IP |
| Suspicious process detection | MITRE T1059 — certutil, mshta, wscript, regsvr32 |
| Lateral movement detection | MITRE T1021 — multi-host auth from single IP |
| Severity classification | Critical / High / Medium / Low |
| Structured JSON output | Machine-readable alert export |
| CLI argument support | --logs, --output, --verbose |

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection Rule |
|---|---|---|
| Brute Force | T1110 | brute_force_attempt |
| Command and Scripting Interpreter | T1059 | suspicious_process |
| Remote Services | T1021 | lateral_movement |

---

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

Custom log source:
```bash
python main.py --logs /path/to/logs.json --output reports/custom_report.json
```

---

## Sample Output

```
=======================================================
  SECURITY INCIDENT REPORT - SOC AUTOMATION ENGINE
  Generated: 2026-05-06 10:05:00 UTC
=======================================================

  Total Alerts: 4

  [1] [HIGH] Brute Force Attempt Detected
      MITRE        : T1110 - Brute Force
      Source IP    : 192.168.1.10
      Attempts     : 5
      First Seen   : 2026-05-06T10:01:00
      Last Seen    : 2026-05-06T10:01:40
```

---

## Extending Detection Rules

Add a new rule to rules/rules.yaml:
```yaml
- name: suspicious_process
  description: "Detect attacker tooling execution"
  threshold: 1
  severity: medium
  mitre: T1059
  processes:
    - certutil.exe
    - mshta.exe
```

Register the handler in detection/engine.py and the pipeline picks it up automatically.

---

## Roadmap

- Real-time log streaming (tail -f / inotify)
- Elasticsearch storage backend
- Sigma rule format support
- Webhook / Slack alerting
- Time-windowed correlation engine

---

## Author

Built by a SOC L2 Analyst | GitHub: github.com/demonchant | TryHackMe: tryhackme.com/p/oladapodamiey
