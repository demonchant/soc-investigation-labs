from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        exec_f   = next((f for f in findings if f["domain"]=="EXECUTIVE"), None)
        domain_f = [f for f in findings if f["domain"] not in ("EXECUTIVE","TREND","ROADMAP")]
        other_f  = [f for f in findings if f["domain"] in ("TREND","ROADMAP")]
        r = []
        r.append("="*68)
        r.append("  SECURITY POSTURE DASHBOARD — EXECUTIVE REPORT")
        r.append("  Generated   : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Period      : " + data.get("assessment_period","current"))
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low".format(
            counts.get("critical",0), counts.get("high",0),
            counts.get("medium",0),   counts.get("low",0)))
        r.append("="*68)
        r.append("")
        if exec_f:
            lbl = SEV_LABEL.get(exec_f["severity"],"[?]")
            r.append("  {} {}".format(lbl, exec_f["title"]))
            r.append("  " + exec_f["detail"])
            r.append("  Action: " + exec_f["recommendation"])
            r.append("")
        r.append("  DOMAIN SCORECARD:")
        r.append("")
        for f in domain_f:
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  {} {}".format(lbl, f["title"]))
            r.append("       " + f["detail"])
            r.append("       Fix: " + f["recommendation"])
            r.append("")
        for f in other_f:
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  {} [{}] {}".format(lbl, f["domain"], f["title"]))
            r.append("       " + f["detail"])
            r.append("       Fix: " + f["recommendation"])
            r.append("")
        r.append("="*68)
        return "\n".join(r)
