from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts = Counter(f["severity"] for f in findings)
        owasp  = Counter(f.get("owasp_category","?").split(" - ")[-1] for f in findings)
        r = []
        r.append("="*65)
        r.append("  API SECURITY REPORT — OWASP API Top 10")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Findings: {}  |  {} Critical  |  {} High".format(
            len(findings),counts.get("critical",0),counts.get("high",0)))
        r.append("="*65)
        r.append("")
        for cat, cnt in sorted(owasp.items(), key=lambda x: -x[1]):
            r.append("  {:<50}: {} finding(s)".format(cat, cnt))
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {}".format(i,lbl,f["category"].upper(),f["title"]))
            r.append("       Endpoint : " + f["endpoint"])
            r.append("       Detail   : " + f["detail"])
            r.append("       MITRE    : " + f["mitre_technique"])
            if f.get("owasp_category"): r.append("       OWASP    : " + f["owasp_category"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
