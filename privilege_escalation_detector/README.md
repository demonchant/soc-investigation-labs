# 🔴 Privilege Escalation Detector — Token & Permission Abuse Analyzer

> Detects Windows UAC bypasses, Linux SUID/sudo abuses, token impersonation, and kernel exploit indicators across 16 detection rules mapped to MITRE ATT&CK.

## Why This Matters

After initial access, privilege escalation is the attacker's most critical step — without it they're limited to a standard user account. This detector catches the techniques before escalation succeeds and the attacker achieves persistence as SYSTEM/root.

## Detection Rules

### Windows (9 Rules)
| Rule ID | Technique | MITRE |
|---|---|---|
| WIN-PRIVESC-001 | fodhelper UAC bypass | T1548.002 |
| WIN-PRIVESC-002 | eventvwr spawning shell | T1548.002 |
| WIN-PRIVESC-003 | sdclt /kickoffelev | T1548.002 |
| WIN-PRIVESC-004 | SeImpersonatePrivilege (JuicyPotato, PrintSpoofer) | T1134.001 |
| WIN-PRIVESC-006 | Unquoted service path | T1574.009 |
| WIN-PRIVESC-007 | AlwaysInstallElevated MSI | T1548.002 |
| WIN-PRIVESC-009 | BYOVD kernel exploit | T1068 |

### Linux (8 Rules)
| Rule ID | Technique | MITRE |
|---|---|---|
| LIN-PRIVESC-001 | SUID binary enumeration | T1548.001 |
| LIN-PRIVESC-003 | GTFOBins sudo escape | T1548.003 |
| LIN-PRIVESC-005 | LD_PRELOAD injection | T1574.006 |
| LIN-PRIVESC-007 | Docker privileged escape | T1611 |
| LIN-PRIVESC-008 | /etc/passwd root injection | T1098 |

## Chain Detection

When one user triggers **3+ rules** on the same host, a `PRIVESC_CHAIN_DETECTED` CRITICAL alert fires — indicating a systematic attack playbook, not accidental activity.

## Usage

```bash
python generate_sample_data.py
python privilege_escalation_detector.py sample_process_events.ndjson report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
