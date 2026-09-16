"""Cloud Misconfiguration Report Generator."""
from datetime import datetime
from collections import Counter

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts = Counter(f["severity"] for f in findings)
        r = []
        r.append("="*65)
        r.append("  CLOUD MISCONFIGURATION SCAN REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Findings  : " + str(len(findings)) +
                 "  |  " + str(counts.get("critical",0)) + " Critical" +
                 "  |  " + str(counts.get("high",0)) + " High" +
                 "  |  " + str(counts.get("medium",0)) + " Medium")
        r.append("="*65)
        for i, f in enumerate(findings, 1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("")
            r.append("  [" + str(i) + "] " + lbl + " " + f["title"])
            r.append("       Resource : " + f["resource"])
            r.append("       Detail   : " + f["detail"])
            r.append("       MITRE    : " + f["mitre_technique"])
            if f.get("cis_control"):
                r.append("       CIS      : " + f["cis_control"])
            r.append("       Fix      : " + f["recommendation"])
        r.append("")
        r.append("="*65)
        return "\n".join(r)
