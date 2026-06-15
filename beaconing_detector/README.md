# 🔴 Beaconing Detector — C2 Communication Pattern Analyzer

> Detects malware beaconing to Command & Control servers using statistical analysis of network connection intervals.

## Why This Matters

Most AV/EDR tools detect known malware signatures. This tool catches **unknown C2 implants** by identifying the *behavioral fingerprint* of beaconing — regular, low-jitter connections that no human browsing pattern produces.

**Real-world applicability:** Cobalt Strike, Metasploit Meterpreter, custom RATs, and nation-state implants all beacon. This catches them agnostically.

## MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|---|---|---|
| Application Layer Protocol | T1071 | Command & Control |
| Non-Standard Port | T1571 | Command & Control |
| Web Service C2 | T1102 | Command & Control |
| Fallback Channels | T1008 | Command & Control |

## Detection Logic

```
For each unique (src_ip → dst_ip:port) connection pair:
  1. Collect all connection timestamps
  2. Calculate inter-arrival intervals
  3. Compute Coefficient of Variation (CV = stdev/mean)
     → Low CV = highly regular = suspicious
  4. Compute Jitter Score: % of intervals within ±20% of median
     → High % = malware-like regularity
  5. Composite Beacon Score (0–100):
     - Regularity Score  (40 pts): 1 - CV
     - Jitter Score      (30 pts): jitter fraction
     - Volume Score      (20 pts): connection count
     - Port Anomaly      (10 pts): non-standard port
  6. Alert if score ≥ 70
```

## Architecture

```
sample_netflow.ndjson
        │
        ▼
  parse_netflow_log()
        │  builds BeaconCandidate objects per (src→dst:port)
        ▼
  beacon_score()
        │  CV + jitter + volume + port analysis
        ▼
  run_detection()
        │  threshold filtering + severity grading
        ▼
  print_report() + beacon_report.json
```

## Usage

```bash
# Step 1: Generate realistic sample data
python generate_sample_data.py

# Step 2: Run detection
python beaconing_detector.py sample_netflow.ndjson beacon_report.json

# Step 3: Review alerts
cat beacon_report.json | python -m json.tool
```

## Sample Output

```
══════════════════════════════════════════════════════════════════════
  BEACONING DETECTOR — THREAT REPORT
══════════════════════════════════════════════════════════════════════
  🚨 2 beaconing host(s) detected

  [1] HIGH — Score: 91.5/100
      192.168.1.105 → 185.220.101.47:443 (evil-c2.example.com)
      Interval: 61.2s avg | CV: 0.0821 | Jitter: 94% in window
      Connections: 35 | MITRE: T1071 / T1571
      Action: Isolate host and capture full PCAP...

  [2] HIGH — Score: 87.3/100
      10.0.0.88 → 91.108.4.200:4444
      Interval: 120.4s avg | CV: 0.0614 | Jitter: 96% in window
      Connections: 28 | MITRE: T1071 / T1571
```

## Input Format

NDJSON (one JSON object per line):
```json
{"timestamp": "2024-01-15T10:30:00Z", "src_ip": "192.168.1.105", "dst_ip": "185.220.101.47", "dst_port": 443, "dst_host": "example.com"}
```

## Tuning

Adjust thresholds in `CONFIG` dict:
- `cv_threshold`: Lower = catches only very regular beacons (fewer FPs)
- `beacon_score_threshold`: Raise to 80+ for high-confidence-only alerts
- `jitter_window_pct`: Set to 0.30 if targeting Cobalt Strike's default 30% jitter
- `known_good_hosts`: Add your org's CDN/update servers

## Deployment Context

| Environment | Integration Point |
|---|---|
| Enterprise SOC | Consume from Zeek/Bro conn.log or firewall NDJSON export |
| SIEM-less env | Run as cron job against raw firewall logs |
| Threat Hunting | Point at historical PCAP-converted logs |

## Author

**Oladapo Damilola (Wizardskull)**  
SOC L2 Analyst | Detection Engineer  
CompTIA Security+ | Certified SOC Analyst (EC-Council)  
GitHub: [@demonchant](https://github.com/demonchant)
