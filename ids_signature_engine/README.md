# IDS Signature Engine

> A regex-based Intrusion Detection System engine that matches network packet payloads against a signature library. Modelled after Snort/Suricata rule processing — supports port filtering, protocol filtering, and multi-category signature matching.

---

## Signatures Included

| ID | Name | MITRE | Severity |
|---|---|---|---|
| SIG-001 | Web Shell Command Execution | T1505.003 | Critical |
| SIG-002 | DNS Tunneling Oversized Query | T1071.004 | High |
| SIG-003 | SQL Injection Attempt | T1190 | High |
| SIG-004 | Directory Traversal Attack | T1190 | High |
| SIG-005 | EternalBlue SMB Exploit | T1210 | Critical |
| SIG-006 | PowerShell Download Cradle | T1059.001 | Critical |
| SIG-007 | Cross-Site Scripting (XSS) | T1059.007 | Medium |
| SIG-008 | Cobalt Strike Beacon | T1071.001 | Critical |
| SIG-009 | PE Executable Transfer | T1105 | High |

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
