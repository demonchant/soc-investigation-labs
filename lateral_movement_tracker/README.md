# 🔴 Lateral Movement Tracker — Internal Network Propagation Detector

> Builds a directed authentication graph from Windows/Linux auth logs and uses BFS chain analysis to detect Pass-the-Hash, Pass-the-Ticket, and multi-hop attacker propagation.

## Why This Matters

After initial access, attackers move laterally to reach high-value targets (Domain Controllers, finance systems). This is the hardest phase to detect because they use legitimate credentials and protocols. This tool catches the *pattern* of movement, not just individual events.

## MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| Remote Services | T1021 |
| Pass the Hash | T1550.002 |
| Pass the Ticket | T1550.003 |
| Remote Desktop Protocol | T1021.001 |
| WMI | T1047 |

## Architecture

```
Auth Events (NDJSON)
       │
       ▼
  AuthGraph Builder
  (directed graph: src_host → dst_host)
       │
       ▼
  BFS Chain Finder
  (finds multi-hop auth chains within time window)
       │
       ▼
  Chain Scorer
  - Hop count (longer = more suspicious)
  - Speed (fast = automated = malicious)
  - Service account usage
  - Protocol diversity
       │
       ▼
  Alerts + JSON Report
```

## Usage

```bash
python generate_sample_data.py
python lateral_movement_tracker.py sample_auth_events.ndjson report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
