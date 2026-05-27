# Network Anomaly Detection Engine

> Statistical + rule-based network flow analysis engine. Builds per-host behavioural baselines using mean/stddev profiling, then detects anomalies via Z-score deviation and 7 MITRE ATT&CK-mapped detection modules — all from stdlib only, no external dependencies.

---

## Architecture

```
Network Flow Data (JSON / PCAP-exported)
        |
  Flow Analyzer  (port risk, volume class, protocol enrichment)
        |
  Baseline Profiler  (per-IP mean + stddev for bytes/duration)
        |
  Anomaly Engine  (Z-score + 7 rule modules)
        |
  Report Generator  (severity-sorted, MITRE-mapped)
```

---

## Detection Modules

| Module | MITRE | Trigger |
|---|---|---|
| Large outbound transfer | T1048 | bytes_sent > 200KB |
| Port / host scanning | T1046 | ≥5 unique ports or hosts |
| C2 beaconing | T1071 | Low-variance repeated sessions |
| DNS tunneling | T1071.004 | DNS payload > 4KB |
| SMB lateral movement | T1021.002 | SMB transfer > 500KB |
| High-risk port connection | T1572 | Ports 4444/1337/31337/9001/6667 |
| Z-score volume anomaly | T1030 | |Z| ≥ 2.5 standard deviations |

---

## Quick Start

```bash
python main.py
python main.py --flows /path/to/flows.json --output reports/result.json
```

---

## Roadmap

- Live PCAP capture via Scapy
- Sliding time-window baseline updates
- GeoIP enrichment per destination
- Elasticsearch / Kibana output
- Sigma rule export

---

## Author

SOC L2 Analyst | github.com/demonchant
