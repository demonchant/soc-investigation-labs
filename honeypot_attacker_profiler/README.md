# Honeypot Log Analyser & Attacker Profiler

> Ingests honeypot interaction logs (SSH, HTTP, FTP, RDP), aggregates events into attacker sessions, classifies MITRE ATT&CK TTPs from command payloads and actions, extracts structured IOCs, and generates threat actor profiling reports — all from stdlib, no external dependencies.

---

## Architecture

```
Honeypot Logs (SSH / HTTP / FTP / RDP events)
        |
  Session Aggregator  (group by attacker IP)
        |
  TTP Classifier  (regex payload analysis + action mapping → MITRE)
        |
  IOC Extractor  (IPs, URLs, dropped files, credentials, web shells)
        |
  Report Generator  (threat score + actor profile + IOC summary)
        |
  JSON Export  (machine-readable, SIEM / MISP-ready)
```

---

## Detection Coverage

| Service | Attack Type | MITRE Technique |
|---|---|---|
| SSH | Brute force → valid account → tool download | T1110, T1078, T1105 |
| SSH | Cron persistence setup | T1053.003 |
| SSH | Credential dumping (/etc/shadow) | T1003.008 |
| SSH | Hidden file staging (/tmp/.) | T1564.001 |
| HTTP | Config file probing (.env, wp-admin) | T1083 |
| HTTP | SQL injection | T1190 |
| HTTP | XSS / script injection | T1059.007 |
| FTP | Web shell upload | T1505.003 |
| RDP | Password spraying | T1110 |

---

## Threat Scoring

Each attacker receives a 0–100 threat score based on:
- Number of unique MITRE techniques identified (×10 each)
- Volume of credential attempts (capped at 30 pts)
- Number of commands executed (capped at 40 pts)

Tiers: **MEDIUM** (0–44) | **HIGH** (45–69) | **CRITICAL** (70–100)

---

## Quick Start

```bash
python main.py
python main.py --logs /path/to/honeypot.json --output reports/actors.json
```

---

## IOCs Extracted Per Session

- Malicious attacker IPs
- Malicious URLs (payload download links)
- Dropped file paths (/tmp/, /var/www/)
- Compromised credentials (successful auth pairs)
- Web shell filenames and upload paths

---

## Roadmap

- Live SSH/HTTP honeypot listener (Paramiko / Flask)
- GeoIP resolution via MaxMind GeoLite2
- Automatic IOC export to MISP / OpenCTI
- STIX 2.1 threat actor bundle output
- Telegram alert on new attacker session

---

## Author

SOC L2 Analyst | github.com/demonchant
