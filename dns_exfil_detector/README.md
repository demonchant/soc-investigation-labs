# 🔴 DNS Exfiltration Detector — Data Theft via DNS Tunnel Analysis

> Detects data exfiltration through DNS tunneling by analyzing subdomain entropy, NXDOMAIN ratios, query volume, and encoding patterns. No external APIs required.

## Why This Matters

DNS is trusted by nearly every network. Attackers exploit this by encoding stolen data in subdomain labels — tools like **dnscat2**, **iodine**, and **DNSExfiltrator** are freely available and widely used. This tool catches them all via behavioral analysis, not signatures.

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Exfiltration Over DNS | T1048.001 | DNS as covert channel |
| DNS Application Protocol | T1071.004 | C2 via DNS |
| Standard Encoding | T1132.001 | base32/base64 in labels |

## Detection Signals

| Signal | Threshold | Why |
|---|---|---|
| Subdomain entropy | ≥ 3.5 bits | Encoded data is high entropy |
| Subdomain length | ≥ 40 chars | DNS labels max 63; long = data |
| NXDOMAIN ratio | ≥ 60% | Tunnel probing non-existent hosts |
| Unique subdomains | ≥ 20 | Each query = new data chunk |
| Query rate | ≥ 30/min | High throughput = active exfil |

## Real Tool Fingerprints Detected

- **dnscat2**: High entropy labels, consistent apex domain
- **iodine**: NULL record type, very high query volume
- **DNSExfiltrator**: base32 encoded subdomains, NXDOMAIN ratio ≈ 0

## Usage

```bash
python generate_sample_data.py
python dns_exfil_detector.py sample_dns.ndjson dns_report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
