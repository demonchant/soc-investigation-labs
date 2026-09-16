# Threat Hunting Workbook

> Executes structured, hypothesis-driven threat hunts against process, network, and authentication log data. Each hunt starts with a written hypothesis describing what attacker behaviour to look for and why, then runs analytic queries to confirm or disprove it.

---

## Hunt Hypotheses

| ID | Hypothesis | MITRE | Severity |
|---|---|---|---|
| HUNT-001 | Office apps spawning PowerShell/cmd = phishing execution | T1566.001 | Critical |
| HUNT-002 | Certutil/bitsadmin used to download files = LOLBin abuse | T1105 | Critical |
| HUNT-003 | One account → 3+ hosts via NTLM = pass-the-hash lateral movement | T1550.002 | Critical |
| HUNT-004 | svchost.exe running from AppData/Temp = process masquerading | T1036.005 | High |
| HUNT-005 | PowerShell/cmd making outbound connections = C2 beacon | T1071.001 | High |

---

## Hunting Methodology

Each hunt follows the structured threat hunting loop:

1. **Hypothesis** — articulate what attacker behaviour you expect to see and why
2. **Data source** — identify which logs contain the relevant evidence
3. **Analytic** — write the detection logic (parent-child, threshold, pattern match)
4. **Result** — HIT (evidence found) or MISS (hypothesis not confirmed in dataset)
5. **Finding** — document evidence with host, user, timestamp, and MITRE technique

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
