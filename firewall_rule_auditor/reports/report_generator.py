"""Firewall Audit Report Generator."""
from datetime import datetime

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, rule_count):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        c = sum(1 for f in findings if f["severity"]=="critical")
        h = sum(1 for f in findings if f["severity"]=="high")
        m = sum(1 for f in findings if f["severity"]=="medium")
        r = []
        r.append("="*65)
        r.append("  FIREWALL RULE AUDIT REPORT")
        r.append("  Generated   : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Rules Audited: " + str(rule_count) + "  |  Findings: " + str(len(findings)))
        r.append("  " + str(c) + " Critical  |  " + str(h) + " High  |  " + str(m) + " Medium")
        r.append("="*65)
        for i, f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("")
            r.append("  [" + str(i) + "] " + lbl + " [" + f["rule_id"] + "] " + f["title"])
            r.append("       Detail  : " + f["detail"])
            r.append("       MITRE   : " + f["mitre_technique"])
            r.append("       Action  : " + f["recommendation"])
        r.append("")
        r.append("="*65)
        return "\n".join(r)
