# UEBA — User Behaviour Analytics & Insider Threat Detector

> Builds per-user behavioural profiles then detects deviations indicating insider threats or compromised accounts: off-hours access, bulk data exfiltration, USB data theft, impossible travel, personal email staging, admin tool abuse, and high-risk country logins.

---

## Detection Modules

| Threat | Severity | MITRE |
|---|---|---|
| Off-hours system access | Medium | T1078 |
| Bulk data download (>500 files or >1GB) | Critical | T1005 |
| USB storage insertion + file copy | Critical | T1052.001 |
| Impossible travel (multi-country session) | Critical | T1078 |
| Data sent to personal email with attachments | High | T1048.003 |
| Admin tool / privileged right usage | High | T1078.002 |
| Login from high-risk country | Critical | T1078 |

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
