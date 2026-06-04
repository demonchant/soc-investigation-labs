# SOC Metrics & KPI Dashboard

> Computes the core SOC performance indicators from alert and incident data. Tracks MTTA, MTTR, MTTC, MTTI, true/false positive rates, SLA compliance breaches, and analyst workload distribution — producing a monthly KPI report.

---

## Metrics Computed

| KPI | Definition |
|---|---|
| MTTA | Mean Time to Acknowledge — avg mins from alert creation to first analyst action |
| MTTR | Mean Time to Resolve — avg mins from alert creation to closure |
| MTTC | Mean Time to Contain — avg hours from incident creation to containment |
| MTTI | Mean Time to Resolve (Incident) — avg hours from creation to full resolution |
| TP Rate | True positive rate — % of alerts confirmed as real threats |
| FP Rate | False positive rate — % of alerts that were noise |
| SLA Compliance | % of alerts acknowledged within severity-based time targets |

---

## SLA Targets

| Severity | Acknowledge |
|---|---|
| Critical | 15 minutes |
| High | 30 minutes |
| Medium | 60 minutes |

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
