# SOAR Playbook Engine

> A Security Orchestration, Automation and Response (SOAR) engine that executes JSON-defined incident response playbooks against live alerts. Automates containment, enrichment, notification, and ticketing actions with a full step-by-step audit trail.

---

## Architecture

```
Incident Alert (INC-001 / 002 / 003)
        |
  Playbook Selector  (trigger → playbook mapping)
        |
  Playbook Runner  (sequential step execution + on_fail branching)
        |
  Action Library  (15 simulated response actions)
        |
  Execution Report  (full audit trail per step)
```

---

## Playbooks

| Playbook | Trigger | Steps | MITRE |
|---|---|---|---|
| Phishing Email Response | phishing_alert | 7 | T1566 |
| Brute Force Lockout | brute_force_alert | 6 | T1110 |
| Malware / Ransomware Containment | malware_alert | 8 | T1486 |

---

## Action Library (15 Actions)

| Action | What It Does |
|---|---|
| notify_analyst | Sends Slack + email alert |
| extract_iocs | Pulls IPs, URLs, domains, hashes from incident |
| reputation_check | Queries VirusTotal / AbuseIPDB |
| quarantine_email | Removes email from mailbox + notifies user |
| block_sender_domain | Pushes block rule to email gateway |
| block_ip | Pushes block rule to perimeter firewall |
| check_account_status | Verifies MFA, last login, compromise indicators |
| lock_account | Disables account + forces password reset |
| geoip_lookup | Resolves source IP to country/ISP |
| isolate_host | Network-isolates endpoint (EDR-style) |
| snapshot_host | Creates memory + disk snapshot for forensics |
| collect_forensic_artifacts | Captures processes, connections, registry, prefetch |
| block_c2_iocs | Pushes C2 IP/domain blocks to firewall + proxy |
| notify_management | Escalates to CISO + SOC Manager |
| create_ticket | Opens incident ticket in SOC queue |

---

## On-Fail Branching

Each step defines behaviour on failure:
- `continue` — log failure and proceed to next step
- `stop` — halt playbook execution
- `escalate` — halt and flag for human escalation

---

## Quick Start

```bash
python main.py
python main.py --incidents data/incidents.json --output reports/soar.json
```

---

## Roadmap

- Conditional branching (if reputation == malicious → isolate_host)
- Parallel step execution (asyncio)
- Live Jira/ServiceNow ticket creation
- Real Slack/PagerDuty notification integration
- Playbook performance metrics (MTTR tracking)

---

## Author

SOC L2 Analyst | github.com/demonchant
