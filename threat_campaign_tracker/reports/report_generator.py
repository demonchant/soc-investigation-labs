from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        n_inc    = len(data.get("incidents", []))
        r = []
        r.append("="*68)
        r.append("  THREAT ACTOR CAMPAIGN TRACKER — CORRELATION REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Incidents Analyzed: {}  |  Correlations Found: {}".format(n_inc, len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium".format(
            counts.get("critical",0), counts.get("high",0), counts.get("medium",0)))
        r.append("="*68)
        r.append("")
        r.append("  NOTE: Attribution findings are HYPOTHESES for hunt prioritization,")
        r.append("  not confirmed actor identification. Verify against current threat intel.")
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} {}".format(i, lbl, f["title"]))
            r.append("       " + f["detail"])
            if f["related_incidents"]:
                r.append("       Incidents: " + ", ".join(f["related_incidents"]))
            r.append("       Basis: " + f["mitre_technique"])
            r.append("       Next : " + f["recommendation"])
            r.append("")
        r.append("="*68)
        return "\n".join(r)
