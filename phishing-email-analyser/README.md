# Phishing Email Analyser

> Automated phishing triage engine that analyses email headers (SPF/DKIM/DMARC, typosquatting, display name spoofing, reply-to anomalies) and body content (urgency language, BEC patterns, credential harvesting, malicious URLs, macro attachments) to produce a scored verdict and response recommendation.

---

## Architecture

```
Email Records (JSON / raw .eml)
        |
  Email Parser
        |
  Header Analyser     Content Analyser
  (auth + spoofing)   (body + attachments)
        |                   |
        +------- Risk Scorer -------+
                      |
             Report Generator
```

---

## Detection Checks

### Header Analysis
| Check | Signal |
|---|---|
| SPF FAIL/SOFTFAIL | Sender IP not authorised by domain |
| DKIM FAIL/NONE | Email signature missing or invalid |
| DMARC FAIL/NONE | Domain alignment policy failed |
| Display name spoofing | Brand name in display ≠ sending domain |
| Reply-To mismatch | Replies route to different domain / free mail |
| High-risk country IP | Sending IP from RU/CN/KP/IR/SY/BY |
| Typosquatting | Domain matches known brand lookalike patterns |

### Content Analysis
| Check | Signal |
|---|---|
| Urgency language | Account suspension, 24-hour deadlines |
| Credential harvesting | "Click here to verify", "Enter your password" |
| BEC / CEO fraud | Wire transfer requests, confidentiality demands |
| Malicious URLs | IP-based URLs, suspicious TLDs, token parameters |
| URL shorteners | bit.ly, tinyurl used to mask destination |
| Malicious attachment | .exe, .scr, .bat, .vbs, .ps1, .hta |
| Macro-enabled documents | .docm, .xlsm — common malware delivery |

---

## Scoring

| Score | Verdict | Action |
|---|---|---|
| 70–100 | PHISHING | Quarantine + block sender domain |
| 45–69 | SUSPICIOUS | Hold for analyst review + sandbox |
| 20–44 | LOW_RISK | Deliver with warning banner |
| 0–19 | CLEAN | Deliver normally |

Score = (header_score × 0.4) + (content_score × 0.6)

---

## Quick Start

```bash
python main.py
python main.py --emails data/emails.json --output reports/results.json
```

---

## Roadmap

- Raw .eml file parsing (email stdlib module)
- VirusTotal URL reputation lookup integration
- IMAP live mailbox ingestion
- Attachment sandboxing integration (Any.run / Cuckoo)
- Automated SOC ticket creation

---

## Author

SOC L2 Analyst | github.com/demonchant
