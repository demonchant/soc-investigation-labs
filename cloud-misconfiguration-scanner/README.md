# Cloud Misconfiguration Scanner

> Audits AWS infrastructure configuration against security best practices and CIS AWS Benchmark controls. Detects public S3 buckets, internet-exposed database and management ports, IAM users without MFA, stale access keys, overprivileged accounts, CloudTrail logging gaps, and weak password policies.

---

## Checks Performed

| Area | Check | Severity |
|---|---|---|
| S3 | Public write access | Critical |
| S3 | Sensitive bucket publicly readable | Critical |
| S3 | Encryption disabled | High |
| S3 | Versioning disabled | Medium |
| S3 | Access logging disabled | Medium |
| Security Groups | DB port (MySQL/Postgres) from internet | Critical |
| Security Groups | Management port (RDP/SSH/VNC) from internet | Critical |
| IAM | Console access without MFA | Critical |
| IAM | Multiple active access keys | High |
| IAM | Stale key (unused >90 days) | High |
| IAM | AdministratorAccess / PowerUserAccess | High |
| CloudTrail | Logging disabled | Critical |
| CloudTrail | Not multi-region | High |
| CloudTrail | Log validation disabled | Medium |
| Password Policy | Weak policy (length/complexity/expiry) | High |

---

## Standards Referenced

- CIS AWS Foundations Benchmark v2.0
- MITRE ATT&CK Cloud Matrix
- AWS Well-Architected Framework (Security Pillar)

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
