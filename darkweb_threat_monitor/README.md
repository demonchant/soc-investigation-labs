# Dark Web and Threat Feed Monitor

> Processes intelligence from dark web forum scrapes, paste site monitors, ransomware leak site trackers, certificate transparency logs, and vulnerability feeds. Scores each item by severity, confidence, and threat type — outputs a prioritised response queue with specific recommended actions per threat category.

---

## Architecture

```
Threat Intelligence Feed (JSON)
        |
  Threat Analyser  (severity + confidence + type scoring)
        |
  Risk Tier Classification  (CRITICAL / HIGH / MEDIUM / LOW)
        |
  Report Generator  (prioritised queue + response actions)
        |
  JSON Export  (SIEM / SOAR-ready)
```

---

## Feed Sources Simulated

| Feed | Source | What It Detects |
|---|---|---|
| darkweb_forum_scrape | BreachForums / XSS | Credential dumps, access sales |
| paste_monitor | Pastebin / GitHub Gists | API key leaks, PII dumps |
| ransomware_tracker | LockBit, ALPHV sites | Victim listings, data claims |
| vulnerability_intel | AlienVault OTX / ExploitDB | IOC matches, PoC exploits |
| cert_transparency | CT Log monitoring | Typosquat / phishing domains |

---

## Threat Categories and Responses

| Type | Immediate Response |
|---|---|
| credential_leak | Force password reset + enforce MFA |
| ransomware_mention | Initiate IR plan, engage legal + DPO |
| source_code_leak | Revoke API keys, rotate all secrets |
| ioc_match | Block IOC at perimeter, hunt internally |
| access_sale | Audit VPN/RDP, reset remote credentials |
| phishing_infrastructure | Register typosquat, block at email gateway |
| pii_exposure | Notify DPO, assess GDPR obligations |
| exploit_available | Emergency patch or WAF interim control |

---

## Scoring Formula

`Risk Score = (Severity Points + Type Points) x Confidence Multiplier`

| Confidence | Multiplier |
|---|---|
| Confirmed | x1.5 |
| High | x1.2 |
| Medium | x1.0 |
| Low | x0.6 |

---

## Quick Start

```bash
python main.py
python main.py --feed data/threat_feed.json --output reports/threat_report.json
```

---

## Roadmap

- Live RSS/API polling for ransomware tracker sites
- Shodan exposure monitoring integration
- Automatic IOC export to MISP
- Email/Slack alerting on new critical items
- Domain monitoring via certificate transparency streaming

---

## Author

SOC L2 Analyst | github.com/demonchant
