# Threat Intel Enrichment Tool

> A production-style SOC threat intelligence pipeline for enriching IPs, domains, and file hashes with reputation data, geographic risk analysis, and structured risk scoring.

---

## Architecture

```
Indicator (IP / Domain / Hash)
        |
  Input Validator (classify_input)
        |
  Cache Check (TTL: 5 min)
        |
  Rate Limiter (sliding window)
        |
  Provider Lookup (Mock / VirusTotal)
        |
  Risk Engine (0-100 score)
        |
  Enriched Result + JSON Export
```

---

## Features

| Feature | Details |
|---|---|
| Indicator classification | IP, Domain, MD5/SHA1/SHA256 hash |
| Multi-source enrichment | VirusTotal, AbuseIPDB, Shodan, AlienVault OTX |
| Risk scoring engine | 0-100 score with Critical/High/Medium/Low tier |
| Geographic risk scoring | High-risk country weighting (RU, CN, KP, IR, SY) |
| Category scoring | Malware, phishing, C2, botnet, ransomware |
| Deterministic mock data | Seed-based results, consistent per indicator |
| In-memory cache | 5-minute TTL, per-indicator deduplication |
| Rate limiting | Sliding window — 10 req/60s |
| Batch mode | Multi-indicator analysis with JSON export |
| CLI + interactive mode | Supports --indicator flag and interactive shell |

---

## Risk Score Breakdown

| Score | Level | Meaning |
|---|---|---|
| 0-29 | LOW | Clean / minimal threat signals |
| 30-49 | MEDIUM | Suspicious activity detected |
| 50-69 | HIGH | Malicious indicators confirmed |
| 70-100 | CRITICAL | Confirmed threat actor infrastructure |

---

## Quick Start

```bash
pip install -r requirements.txt

# Interactive mode
python main.py

# Single indicator
python main.py --indicator 8.8.8.8

# With JSON export
python main.py --indicator 185.220.101.47 --output reports/result.json
```

---

## VirusTotal Integration

Set your API key via environment variable:
```bash
export VT_API_KEY="your_vt_api_key_here"
```

The VirusTotalProvider in providers/virustotal.py is production-ready. Swap out MockProvider in core/enricher.py to activate live lookups.

---

## Sample Output

```
  +-----------------------------------------+
  |  ENRICHMENT RESULT                       
  +-----------------------------------------+
  |  Indicator   : 185.220.101.47
  |  Type        : IP
  |  Reputation  : MALICIOUS
  |  Country     : RU
  |  Detected By : VirusTotal, AbuseIPDB, ThreatFox
  |  Risk Score  : 95/100 [CRITICAL]
  |  Cached      : False
  +-----------------------------------------+
```

---

## Roadmap

- Real VirusTotal v3 API (scaffold ready)
- AbuseIPDB live provider
- Async parallel lookups (asyncio)
- SQLite persistence layer
- SIEM webhook export (Splunk HEC / Elastic)
- STIX/TAXII output format

---

## Author

Built by a SOC L2 Analyst | GitHub: github.com/demonchant | TryHackMe: tryhackme.com/p/oladapodamiey
