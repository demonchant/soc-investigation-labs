# 🔴 LOLBas Detector — Living-off-the-Land Binary & Script Attack Detector

> Detects abuse of 20+ legitimate Windows and Linux system binaries mapped to the LOLBAS project. Includes burst detection for active attack campaigns.

## Why This Matters

Modern attackers rarely drop custom malware. Instead they weaponize tools already on every Windows/Linux machine: certutil, mshta, regsvr32, wmic, bash, curl. This is called "living off the land" and bypasses signature-based AV entirely. This detector catches the technique, not the tool.

## Coverage: 20+ LOLBas/GTFOBins

| Binary | Technique | MITRE |
|---|---|---|
| mshta.exe | Remote HTA execution | T1218.005 |
| regsvr32.exe | Squiblydoo | T1218.010 |
| certutil.exe | File download/decode | T1140 |
| powershell.exe | Encoded execution | T1059.001 |
| wmic.exe | Process creation / XSL | T1218.009 |
| ntdsutil.exe | NTDS.dit dump | T1003.003 |
| vssadmin.exe | Shadow copy delete | T1490 |
| bash | /dev/tcp reverse shell | T1059.004 |
| curl/wget | Pipe-to-shell droppers | T1059.004 |
| nc | Bind/reverse shells | T1059.004 |

## Special: Campaign Burst Detection

If one host uses 4+ different LOLBas tools — it fires a CRITICAL `LOLBAS_CAMPAIGN_BURST` alert, indicating an active hands-on-keyboard attacker running a playbook.

## Usage

```bash
python generate_sample_data.py
python lolbas_detector.py sample_process_events.ndjson lolbas_report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 | GitHub: [@demonchant](https://github.com/demonchant)
