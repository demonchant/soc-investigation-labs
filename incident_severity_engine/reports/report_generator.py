from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]","info":"[INFO]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        scored   = [f for f in findings if f.get("composite_score",0) > 0]
        r = []
        r.append("="*68)
        r.append("  INCIDENT SEVERITY SCORING ENGINE — TRIAGE REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Incidents  : {}  |  Assessments: {}".format(
            len(data.get("incidents",[])), len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low  |  {} Info".format(
            counts.get("critical",0), counts.get("high",0), counts.get("medium",0),
            counts.get("low",0),      counts.get("info",0)))
        r.append("="*68)
        r.append("")
        if scored:
            r.append("  SEVERITY QUEUE (highest priority first):")
            for s in sorted(scored, key=lambda x: -x["composite_score"]):
                r.append("  {:>3}/100  {}  {}".format(
                    s["composite_score"], SEV_LABEL.get(s["severity"],"[?]"), s["incident_id"]))
            r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} {}".format(i, lbl, f["title"]))
            r.append("       " + f["detail"])
            r.append("       Action: " + f["recommendation"])
            r.append("")
        r.append("="*68)
        return "\n".join(r)
