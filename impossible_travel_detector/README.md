# 🔴 Impossible Travel Detector — Geospatial Authentication Anomaly Engine

> Detects account compromise by identifying physically impossible login sequences. Uses the Haversine formula for great-circle distance — zero external API dependencies.

## Why This Matters

When an attacker steals credentials and logs in from a different country, they leave a geospatial footprint. A user can't log in from Lagos at 10:00 AM and London at 10:30 AM — it's physically impossible. This tool catches it automatically.

## MITRE ATT&CK Coverage
`T1078` — Valid Accounts | `T1078.004` — Cloud Accounts | `T1133` — External Remote Services

## Detection Algorithm

```
For each user, for each consecutive login pair:
  1. Lookup geo coordinates for both IPs
  2. Haversine distance = great-circle km between coordinates
  3. Required speed = distance / time_between_logins
  4. Flag if speed > 900 km/h (faster than commercial aircraft)
  
Risk Score Components:
  - Impossible speed:        +60 pts
  - Intercontinental jump:   +20 pts
  - VPN/Tor exit node:       +30 pts
  - < 5 minutes between:     +20 pts
```

## Embedded Geo Intelligence
- 15+ IP range → city/country/coordinates mappings
- Known VPN/Tor exit ranges flagged automatically
- Allowlist for major CDN IPs (prevents false positives on Azure/AWS/Cloudflare)

## Usage

```bash
python generate_sample_data.py
python impossible_travel_detector.py sample_auth_logins.ndjson report.json
```

## Production Extension
Replace `SAMPLE_GEO_DB` with MaxMind GeoLite2 (free) for full IP coverage.

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
