# Firewall Rule Auditor

> Parses firewall rulesets and identifies dangerous misconfigurations — overly permissive ANY rules, internet-exposed management ports, cleartext protocol allowances, stale/unreviewed rules, shadow rules that are never reached, and missing egress controls. All findings mapped to MITRE ATT&CK.

---

## Checks Performed

| Check | Severity | MITRE |
|---|---|---|
| Allow ANY → ANY (all traffic) | Critical | T1190 |
| Management port (RDP/SSH/VNC) exposed to internet | Critical | T1021 / T1110 |
| Dangerous port allowed from internet | Critical | T1021 |
| Cleartext protocol (Telnet/FTP) permitted | High | T1040 |
| No outbound egress control | High | T1048 |
| Shadow rule (never reachable) | Medium | Config drift |
| Stale rule (unreviewed > 365 days) | Medium | Config hygiene |
| Rule never reviewed (no date) | Medium | Config hygiene |
| Undocumented rule (no comment) | Low | Config hygiene |

---

## Quick Start

```bash
python main.py
python main.py --rules data/firewall_rules.json --output reports/audit.json
```

---

## Roadmap

- Live firewall API integration (Palo Alto / Cisco ASA / pfSense)
- Subnet overlap detection (netaddr)
- Rule conflict detection
- Automated remediation script generation

---

## Author

SOC L2 Analyst | github.com/demonchant
