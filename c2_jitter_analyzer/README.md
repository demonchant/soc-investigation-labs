# 🔴 C2 Framework Fingerprinter — Jitter Pattern & Signature Analyzer

> Threat intelligence-grade tool that identifies WHICH C2 framework is in use (Cobalt Strike, Metasploit, Havoc, Sliver, Brute Ratel, Covenant) by fingerprinting their distinctive jitter, URI, User-Agent, and timing signatures.

## Why This Matters

Knowing *that* there's a C2 beacon is step one. Knowing *which framework* tells you: threat actor sophistication, available capabilities (keylogging, lateral movement modules, persistence), and which IR playbook to invoke. This is threat intelligence, not just detection.

## Framework Signatures Database

| Framework | Default Interval | Jitter | MITRE SW |
|---|---|---|---|
| Cobalt Strike | 60s | 0–30% | S0154 |
| Metasploit Meterpreter | 5–15s | 0–10% | S0040 |
| Havoc C2 | 2–5s | 0–50% | — |
| Sliver C2 | 60–300s | 0–15% | — |
| Brute Ratel C4 | 30–60s | 0–20% | S1063 |
| Covenant | 5–10s | 0–10% | — |

## Fingerprinting Dimensions

- **Timing**: Mean interval + jitter CV vs known framework defaults
- **URI patterns**: Malleable profile URI fingerprints
- **User-Agent**: Default agent strings per framework
- **Body size**: Response size ranges
- **HTTP methods**: Framework-specific method patterns

## Usage

```bash
python generate_sample_data.py
python c2_framework_fingerprinter.py sample_http_proxy.ndjson report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
