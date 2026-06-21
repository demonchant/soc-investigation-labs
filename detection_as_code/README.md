# Detection-as-Code Pipeline

Treats Sigma-style detection rules as version-controlled code: lints rule syntax, runs them through a CI-style test suite against attack/benign event corpora, computes deployment readiness scores, and gates promotion to production based on precision/recall thresholds — purple team engineering applied to detection content.

```bash
python main.py
```

SOC L2 Analyst | github.com/demonchant
