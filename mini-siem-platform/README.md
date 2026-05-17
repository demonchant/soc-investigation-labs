# Mini SIEM Platform

> A lightweight but production-structured SIEM that ingests logs, stores them in SQLite, runs a multi-rule detection engine, generates MITRE ATT&CK-mapped alerts, and exposes a RESTful Flask API for SOC dashboard integration.

---

## Architecture

```
Log Ingestion (JSON)
      |
  Normalizer (field validation + schema flattening)
      |
  SQLite Storage (indexed logs + alerts tables)
      |
  Rule Engine (YAML-driven, 4-rule detection)
      |
  Alert Manager (DB-persisted alerts)
      |
  Flask API (SOC dashboard / integration layer)
```

---

## Features

| Feature | Details |
|---|---|
| Log ingestion pipeline | JSON log intake with field validation |
| Normalization layer | Consistent schema across log sources |
| SQLite storage | Indexed logs and alerts tables |
| YAML-driven rule engine | Human-readable, extensible rules |
| Brute force detection | T1110 — threshold-based per IP |
| Credential stuffing detection | T1110.003 — success after failures |
| Suspicious process detection | T1059 — known attacker tooling |
| Lateral movement detection | T1021 — multi-host auth per user |
| Flask REST API | SOC visibility layer with filtering |
| Stats endpoint | Alert counts by severity and rule |

---

## MITRE ATT&CK Coverage

| Technique | ID | Rule |
|---|---|---|
| Brute Force | T1110 | brute_force |
| Credential Stuffing | T1110.003 | suspicious_login_success |
| Command Interpreter Abuse | T1059 | process_anomaly |
| Remote Services | T1021 | multi_host_auth |

---

## Quick Start

```bash
pip install -r requirements.txt

# Run detection pipeline
python main.py

# Start API server
python api/server.py
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| /health | GET | Service health check |
| /alerts | GET | All alerts (filterable by ?severity=high) |
| /alerts/<id> | GET | Alert detail with parsed evidence |
| /logs | GET | Ingested logs (filterable by ?event_type=) |
| /stats | GET | Summary: counts by severity and rule |

---

## Sample API Response

```json
GET /stats
{
  "total_logs_ingested": 12,
  "total_alerts": 5,
  "alerts_by_severity": {"high": 3, "medium": 2},
  "alerts_by_rule": {"brute_force": 1, "process_anomaly": 2, "multi_host_auth": 1}
}
```

---

## Roadmap

- Real-time streaming ingestion (Kafka / Redis pub-sub)
- Elasticsearch backend
- Role-based API access control
- MITRE ATT&CK Navigator export
- Sigma rule format support

---

## Author

Built by a SOC L2 Analyst | GitHub: github.com/demonchant | TryHackMe: tryhackme.com/p/oladapodamiey
