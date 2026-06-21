from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        r = []
        r.append("="*65)
        r.append("  BRUTE FORCE & ACCOUNT LOCKOUT DETECTOR REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Auth Events: {}  |  Findings: {}".format(
            len(data.get("auth_events",[])), len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium".format(
            counts.get("critical",0), counts.get("high",0), counts.get("medium",0)))
        r.append("="*65)
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} {}".format(i, lbl, f["title"]))
            r.append("       " + f["detail"])
            r.append("       MITRE: " + f["mitre_technique"])
            r.append("       Fix  : " + f["recommendation"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
