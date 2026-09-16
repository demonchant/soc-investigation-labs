# Identity Threat Detector

This project analyzes identity provider events for MFA push fatigue, suspicious consent grants, token replay, legacy authentication, and successful access after repeated MFA denial.

## Detection coverage

| Detection | MITRE ATT&CK |
| --- | --- |
| MFA push fatigue | T1621 |
| Suspicious OAuth consent | T1098.003 |
| Token replay across countries | T1528 |
| Legacy authentication success | T1078 |
| MFA denial followed by success | T1078.004 |

## Run

```bash
python main.py
```

The command analyzes `data/identity_events.json`, prints a SOC report, and writes structured findings to `reports/identity_findings.json`.

This is a production structured demonstration that uses synthetic events. Connect the normalized event schema to Okta, Microsoft Entra ID, or another identity provider for operational use.
