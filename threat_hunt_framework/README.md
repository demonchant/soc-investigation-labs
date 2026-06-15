# 🏹 Threat Hunt Framework — Hypothesis-Driven Hunt Orchestrator

> A production-grade threat hunting framework implementing the PEAK methodology (Prepare, Execute, Act, Knowledge). Runs structured hunt hypotheses, tracks evidence confidence, and generates executive hunt reports.

## Why This Matters

Most SOC teams react to alerts. Threat hunters proactively search for attackers who bypassed detection. This framework operationalizes that process — turning ad-hoc hunting into a repeatable, documented, measurable discipline.

## PEAK Methodology Implementation

```
PREPARE  → Define hypotheses (HuntHypothesis objects)
           Map to MITRE ATT&CK
           Identify required data sources

EXECUTE  → ThreatHuntOrchestrator.run_all_hunts()
           Each hypothesis runs against loaded data
           Evidence scored 0–100 confidence

ACT      → Verdict: CONFIRMED / POSSIBLE / UNCONFIRMED
           Prioritized recommendations
           IR escalation triggers

KNOWLEDGE → hunt_report.json
            Documented findings for next hunt
            Detection rule creation candidates
```

## Built-in Hunt Hypotheses (5)

| Hunt ID | Hypothesis | MITRE |
|---|---|---|
| HUNT-001 | High-entropy process names (random malware) | T1036.005 |
| HUNT-002 | Parent process spoofing / Office spawning shells | T1055 |
| HUNT-003 | Non-standard port / protocol anomalies | T1571 |
| HUNT-004 | Off-hours scheduled task persistence | T1053.005 |
| HUNT-005 | Data staging before exfiltration | T1074.001 |

## Architecture

```
hunt_data.ndjson (multi-type: processes, connections, file_events)
        │
        ▼
ThreatHuntOrchestrator
  ├─ load_data()           # organizes events by type
  ├─ run_all_hunts()       # executes all hypotheses
  │    ├─ HUNT-001: entropy analysis
  │    ├─ HUNT-002: process chain analysis
  │    ├─ HUNT-003: port anomaly analysis
  │    ├─ HUNT-004: scheduled task analysis
  │    └─ HUNT-005: staging detection
  └─ generate_report()     # executive summary + recommendations
```

## Extending with Custom Hunts

```python
def my_custom_hunt(data: dict) -> dict:
    findings = []
    # ... your detection logic ...
    return {"findings": findings, "evidence": [...], "confidence": 75}

hypothesis = HuntHypothesis(
    "HUNT-006", "My Custom Hunt",
    "Description of what we're hunting for",
    "T1XXX", "Tactic Name",
    ["data_source_needed"],
    ["ioc_type_produced"],
    my_custom_hunt
)
```

## Sample Output

```
[*] Running 5 hunt hypotheses...
    → HUNT-001: High-Entropy Process Name Detection 🔴 [CONFIRMED] (75%)
    → HUNT-002: Parent Process Spoofing / Unusual Spawn Chain 🔴 [CONFIRMED] (85%)
    → HUNT-003: Non-Standard Port / Protocol Anomaly 🟡 [POSSIBLE] (45%)
    → HUNT-004: Suspicious Scheduled Task Persistence 🟢 [UNCONFIRMED] (10%)
    → HUNT-005: Pre-Exfiltration Data Staging 🟡 [POSSIBLE] (50%)

Overall Verdict: THREAT_CONFIRMED
[IMMEDIATE] Escalate to IR: 2 confirmed threat(s) found
```

## Usage

```bash
python generate_sample_data.py
python threat_hunt_framework.py sample_hunt_data.ndjson hunt_report.json
```

## Author
**Oladapo Damilola (Wizardskull)** | SOC L2 Analyst | Threat Hunter
CompTIA Security+ | Certified SOC Analyst (EC-Council)
GitHub: [@demonchant](https://github.com/demonchant) | TryHackMe: oladapodamiey
