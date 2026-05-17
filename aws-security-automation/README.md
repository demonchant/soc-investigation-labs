# AWS Security Automation System

> A production-style cloud security monitoring pipeline that ingests CloudTrail-format logs, detects suspicious IAM activity across 8 threat signatures, and generates MITRE ATT&CK-mapped incident reports.

---

## Architecture

```
CloudTrail Logs (JSON / S3 / CloudWatch)
        ↓
   Log Collector (format-aware reader)
        ↓
   Normalizer (flat schema extraction)
        ↓
   IAM Detection Engine (8-rule evaluation)
        ↓
   Alert Manager (severity-sorted store)
        ↓
   Report Generator (MITRE-mapped output)
        ↓
   Incident Report (console + JSON export)
```

---

## Detection Rules

| Rule | Event | Severity | MITRE |
|---|---|---|---|
| Root Login | ConsoleLogin + root | Critical | T1078.004 |
| Root Login Without MFA | ConsoleLogin + no MFA | Critical | T1078.004 |
| New Access Key | CreateAccessKey | High | T1098.001 |
| Privilege Escalation | AttachUserPolicy | High | T1098 |
| High-Risk Region | Region in RU/CN/KP/IR/SY | Medium | T1535 |
| New IAM User | CreateUser | Medium | T1136.003 |
| Console Login Failure | ConsoleLogin + failure | Low | T1110 |
| Security Group Modified | AuthorizeSecurityGroupIngress | High | T1562.007 |

---

## Quick Start

```bash
python main.py

# Custom log source
python main.py --logs /path/to/cloudtrail.json --output reports/custom.json
```

---

## Sample Output

```
============================================================
  AWS IAM SECURITY INCIDENT REPORT
  Generated : 2026-05-06 10:10:00 UTC
  Total Alerts : 8
============================================================

  Summary: 2 Critical | 3 High | 2 Medium | 1 Low

  [1] [CRITICAL] Root Account Login Detected
       MITRE          : T1078.004 - Cloud Accounts
       User           : root
       Source IP      : 102.89.12.5
       Region         : RU
       Remediation    : Immediately rotate root credentials. Enable MFA...
```

---

## Extending to Real AWS

1. Install boto3: `pip install boto3`
2. Replace `LogCollector.collect()` with:
```python
import boto3
client = boto3.client("logs")
response = client.filter_log_events(logGroupName="/aws/cloudtrail")
```
3. Add SNS alerting via `boto3.client("sns").publish()`

---

## Roadmap

- [ ] boto3 CloudWatch Logs real-time ingestion
- [ ] AWS Lambda deployment for serverless execution
- [ ] SNS / PagerDuty alert integration
- [ ] DynamoDB persistence layer
- [ ] CloudWatch custom metric alarms
- [ ] GuardDuty finding correlation

---

## Author

Built by a SOC L2 Analyst | [GitHub](https://github.com/demonchant) | [TryHackMe](https://tryhackme.com/p/oladapodamiey)
