from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        summary  = next((f for f in findings if f["rule_id"]=="SUMMARY"), None)
        rest     = [f for f in findings if f["rule_id"] != "SUMMARY"]
        total_h  = sum(f.get("analyst_hours_saved_per_day",0) for f in rest)

        r = []
        r.append("="*68)
        r.append("  ALERT FATIGUE & SOC WORKLOAD OPTIMIZER — REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Rules Analyzed : {}  |  Findings: {}".format(
            len(set(a.get("rule_id") for a in data.get("alert_history",[]))),
            len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low".format(
            counts.get("critical",0), counts.get("high",0),
            counts.get("medium",0),   counts.get("low",0)))
        r.append("  Potential savings: {:.1f} analyst-hours/day if all noise fixed".format(
            total_h))
        r.append("="*68)
        r.append("")
        if summary:
            r.append("  PROGRAM HEALTH: " + summary["title"])
            r.append("  " + summary["detail"])
            r.append("")
        r.append("  TUNING ROADMAP (ranked by analyst-hours-saved/day):")
        r.append("")
        actionable = sorted(
            [f for f in rest if f.get("analyst_hours_saved_per_day",0) > 0],
            key=lambda f: -f["analyst_hours_saved_per_day"])
        for i,f in enumerate(actionable,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {} — saves {:.1f}h/day".format(
                i, lbl, f["rule_id"], f["title"],
                f.get("analyst_hours_saved_per_day",0)))
            r.append("       " + f["detail"])
            r.append("       Fix: " + f["recommendation"])
            r.append("")
        other = [f for f in rest if f.get("analyst_hours_saved_per_day",0) == 0]
        for f in other:
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  {} [{}] {}".format(lbl, f["rule_id"], f["title"]))
            r.append("       " + f["detail"])
            r.append("       Fix: " + f["recommendation"])
            r.append("")
        r.append("="*68)
        return "\n".join(r)
