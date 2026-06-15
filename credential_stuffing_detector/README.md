# 🔴 Credential Stuffing Detector — Authentication Attack Analyzer

> Detects credential stuffing, password spraying, and brute-force attacks by analyzing login failure patterns, IP velocity, user agent entropy, and automation fingerprints.

## Why This Matters

Credential stuffing is responsible for billions of account takeovers annually. Generic rate-limiting catches amateurs — this tool catches sophisticated attacks using distributed IPs, rotating user agents, and low-volume spraying.

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Password Spraying | T1110.003 | Low-volume across many users |
| Credential Stuffing | T1110.004 | Leaked credential replay |
| Valid Accounts | T1078 | Post-compromise indicator |
| External Remote Services | T1133 | Auth endpoint targeting |

## Detection Logic

```
For each source IP:
  1. Count failures, successes, unique users targeted
  2. Compute failure ratio (>85% = spray/stuffing)
  3. Measure inter-request speed (< 500ms = automated)
  4. Calculate User-Agent Shannon entropy (high = bot rotation)
  5. Classify: CREDENTIAL_STUFFING / PASSWORD_SPRAY / BRUTE_FORCE
  6. Escalate if successes detected post-failures
```

## Attack Classification

| Pattern | Detection | Indicator |
|---|---|---|
| Many users, some successes | CREDENTIAL_STUFFING | Leaked list replay |
| Many users, all failures | PASSWORD_SPRAY | Single password, many targets |
| Few users, many attempts | BRUTE_FORCE | Dictionary attack |

## Usage

```bash
python generate_sample_data.py
python cred_stuffing_detector.py sample_auth.ndjson report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
