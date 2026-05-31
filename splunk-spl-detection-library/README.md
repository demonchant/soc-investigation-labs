# Splunk SPL Detection Rule Library

> A detection-as-code library of 10 production-ready Splunk SPL queries mapped to MITRE ATT&CK. Includes a CI/CD-style validation engine that checks rule schema, MITRE format, SPL completeness, and tuning guidance before deployment.

---

## Detection Rules

| ID | Name | MITRE | Severity |
|---|---|---|---|
| SPL-001 | Brute Force Login Detection | T1110 | High |
| SPL-002 | PowerShell Encoded Command | T1059.001 | Critical |
| SPL-003 | Credential Dumping — LSASS Access | T1003.001 | Critical |
| SPL-004 | Lateral Movement — Pass-the-Hash | T1550.002 | Critical |
| SPL-005 | Registry Run Key Persistence | T1547.001 | High |
| SPL-006 | Office App Suspicious Network Connection | T1566.001 | High |
| SPL-007 | DNS Tunneling Detection | T1071.004 | High |
| SPL-008 | Ransomware — VSS Shadow Copy Deletion | T1490 | Critical |
| SPL-009 | Impossible Travel Detection | T1078 | Critical |
| SPL-010 | Service Account Interactive Login | T1078.002 | High |

---

## Rule Schema

Each rule contains:
- **SPL query** with stats, eval, and table commands
- **MITRE ATT&CK** technique ID and name
- **Log source** and relevant Event IDs
- **Tuning notes** — how to reduce false positives
- **Response guidance** — what to do when it fires

---

## Validation Engine

The `SPLValidator` runs pre-deployment checks on every rule:
- Required field completeness
- MITRE ID format (T1234 / T1234.001)
- SPL syntax baseline (index=, pipe operators, table output)
- Aggregation presence (warns on high-volume raw event output)
- Tuning note presence

This mirrors real detection engineering workflows where rules go through peer review and automated CI checks before being pushed to production Splunk.

---

## Quick Start

```bash
python main.py
python main.py --rules data/spl_rules.json --output reports/catalogue.json
```

---

## Roadmap

- Live Splunk SDK integration (push rules to Splunk Enterprise)
- Sigma rule format import/export
- Automated backtest against sample log data
- Rule performance benchmarking (EPS impact estimate)
- GitHub Actions CI/CD pipeline for rule deployment

---

## Author

SOC L2 Analyst | github.com/demonchant
