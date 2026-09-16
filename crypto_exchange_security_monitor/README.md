# Crypto Exchange Security Monitor

> A security detection engine purpose-built for cryptocurrency exchange environments. Detects account takeover chains, wash trading, API abuse, structuring (smurfing), KYC fraud, and impossible travel — all mapped to MITRE ATT&CK and financial compliance regulations (FINRA, FinCEN/BSA, FATF).

---

## Architecture

```
Exchange Event Stream (login / trade / withdrawal / API / KYC events)
        |
  Exchange Security Engine  (7 detection modules)
        |
  Report Generator  (MITRE-mapped + regulatory context)
        |
  Incident Report  (console + JSON export)
```

---

## Detection Modules

| Threat | MITRE / Reg | Detection Logic |
|---|---|---|
| Impossible Travel | T1078.004 | Same user, different countries within session |
| ATO Withdrawal Chain | T1078 + T1098.001 | Risky login → new withdraw API key → withdrawal |
| API Rate Abuse | T1498 | >300 requests/minute per API key |
| Brute Force | T1110 | ≥5 failed logins per user |
| Wash Trading | FINRA Rule 6140 | Matched buy/sell pairs, <5% amount variance |
| Structuring / Smurfing | FinCEN/BSA 31 CFR 1010.314 | Sub-$10K multi-address withdrawals summing >$10K |
| KYC Bypass | FATF Recommendation 10 | Document reuse / identity fraud flags |

---

## Why This Matters

Crypto exchanges face threats that traditional SIEM tools miss entirely:

- **ATO chains**: attacker logs in from VPN (high-risk country), creates API key with withdrawal permissions, drains funds — all in under 2 minutes
- **Wash trading**: coordinated accounts inflate volume to manipulate token prices — a FINRA-regulated offence
- **Structuring**: attackers split large withdrawals into multiple sub-threshold transactions to avoid FinCEN Currency Transaction Reports (CTR threshold: $10,000 USD)

This engine detects all three using chained event correlation, not single-event triggers.

---

## Quick Start

```bash
python main.py
python main.py --events /path/to/events.json --output reports/alerts.json
```

---

## Regulatory References

| Regulation | Area |
|---|---|
| FINRA Rule 6140 | Wash trading / market manipulation |
| FinCEN / BSA 31 CFR 1010.314 | Currency structuring / smurfing |
| FATF Recommendation 10 | KYC / customer due diligence |
| MITRE ATT&CK Cloud Matrix | Account takeover, API abuse |

---

## Roadmap

- Real-time Kafka stream ingestion
- Blockchain address reputation lookup (Chainalysis / Elliptic API)
- Automated SAR (Suspicious Activity Report) generation
- Velocity rules with configurable time windows
- Binance-style compliance dashboard integration

---

## Author

SOC L2 Analyst | github.com/demonchant
