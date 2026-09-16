# Security Telemetry Health Monitor

This project detects failures in the logging pipeline itself. It identifies silent sources, severe volume drops, ingestion delay, parser failure, schema drift, retention risk, and clock skew before those gaps become blind spots during an incident.

## Why it matters

Detection rules cannot protect an environment when their data sources are missing or malformed. This monitor gives a SOC an independent control for telemetry availability and quality.

## Run

```bash
python main.py
```

The bundled fixture represents source health measurements from EDR, DNS, identity, firewall, and cloud audit pipelines. The output includes prioritized remediation guidance and ATT&CK data source context.

This is a production structured demonstration. Operational deployment requires measurements from the real ingestion platform and source specific service objectives.
