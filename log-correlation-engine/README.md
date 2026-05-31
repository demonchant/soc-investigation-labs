# Multi-Source Log Correlation Engine

> Ingests events from Windows Security, Firewall, Proxy, and DNS sources, classifies each event with semantic tags, then applies correlation rules to detect multi-stage attack chains — threats invisible to single-source detection.

---

## Architecture

```
Multi-Source Logs (Windows / Firewall / Proxy / DNS)
        |
  Event Classifier  (semantic tagging per log)
        |
  Correlation Engine  (sequence matching + time-window gating)
        |
  Report Generator  (MITRE-mapped chain alerts)
```

---

## Correlation Rules

| Rule | Sequence | MITRE |
|---|---|---|
| COR-001 | DNS recon → logon attempt | T1595 |
| COR-002 | Brute force burst → successful login | T1110 → T1078 |
| COR-003 | Login success → C2 callback | T1078 → T1071 |
| COR-004 | Multi-host authentication | T1021 |
| COR-005 | Compromise → large outbound transfer | T1048 |
| COR-006 | Full kill chain (all 6 stages) | T1595→T1110→T1078→T1071→T1021→T1048 |

---

## Event Tags

Each log entry is classified with semantic tags: `dns_internal_recon`, `logon_fail`, `logon_fail_burst`, `logon_success`, `c2_connection`, `large_outbound`, `malicious_download`, `ransomware_indicator`, `multi_host_logon`

Correlation rules match sequences of these tags within configurable time windows.

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
