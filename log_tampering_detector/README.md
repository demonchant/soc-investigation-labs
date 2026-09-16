# 🔴 Log Tampering Detector — Anti-Forensics & Log Integrity Analyzer

> Detects attackers clearing, disabling, or tampering with audit logs to cover their tracks. Monitors Windows Event IDs 1102/104/4719, sequence gaps, timestamp anomalies, and Linux log manipulation commands.

## Why This Matters

Log clearing is an attacker's first priority after gaining access. If you can't detect it, the attack becomes invisible. This tool is your last line of defense — it monitors the integrity of your monitoring itself.

## Detection Methods

| Method | What It Catches |
|---|---|
| Event ID monitoring | Log clears (1102, 104), policy changes (4719) |
| Sequence gap analysis | Deleted event records (gaps in record_id sequence) |
| Timestamp anomaly | Out-of-order events (log injection) |
| Log silence gaps | Unexplained quiet periods (service killed) |
| Linux command patterns | `rm`, `truncate`, `auditctl -e 0`, echo overwrite |

## Windows Event IDs Monitored

| Event ID | Meaning | Severity |
|---|---|---|
| 1102 | Security log cleared | CRITICAL |
| 104 | System log cleared | CRITICAL |
| 4719 | Audit policy changed | CRITICAL |
| 1100 | Logging service shutdown | HIGH |
| 4906 | CrashOnAuditFail changed | HIGH |

## Usage

```bash
python generate_sample_data.py
python log_tampering_detector.py sample_event_logs.ndjson report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
