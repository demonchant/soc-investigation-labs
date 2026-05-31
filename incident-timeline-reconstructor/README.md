# Incident Timeline Reconstructor

> Ingests multi-source forensic evidence (Windows logs, Sysmon, Firewall, Proxy, DNS), sorts events chronologically, maps them to MITRE ATT&CK kill chain phases, calculates inter-phase dwell times, identifies patient zero, extracts IOCs, and produces a structured incident report suitable for post-incident review or legal handover.

---

## What It Reconstructs

From raw mixed-source evidence, this tool produces:
- **Chronological event timeline** with source + MITRE technique per event
- **Kill chain phase progression** with first-seen timestamps per phase
- **Dwell time calculation** — total attacker presence in environment
- **Patient zero identification** — first host compromised
- **IOC extraction** — attacker IPs, compromised hosts, MITRE techniques used

---

## Attack Phases Mapped

Reconnaissance → Initial Access → Execution → Command & Control → Persistence → Credential Access → Lateral Movement → Discovery → Privilege Escalation → Collection → Exfiltration → Impact

---

## Demo Scenario

The included dataset reconstructs a full APT intrusion:
DNS recon → Kerberos brute force → credential theft → PowerShell C2 beacon → DCSync → pass-the-hash lateral movement → data staging → 8.5MB exfiltration → ransomware preparation (VSS deletion)

Total dwell time: 41 minutes across 15 forensic events from 5 log sources.

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
