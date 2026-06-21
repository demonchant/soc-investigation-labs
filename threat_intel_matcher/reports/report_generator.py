from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        by_cat   = Counter(f["threat_category"] for f in findings)
        r = []
        r.append("="*65)
        r.append("  THREAT INTEL IOC MATCH REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Events     : {}  |  IOC Matches: {}".format(
            len(data.get("log_events",[])), len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low".format(
            counts.get("critical",0), counts.get("high",0),
            counts.get("medium",0), counts.get("low",0)))
        r.append("="*65)
        r.append("")
        for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
            r.append("  {:<22}: {} match(es)".format(cat, cnt))
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] Matched: {}".format(
                i, lbl, f["ioc_type"].upper(), f["matched_ioc"]))
            r.append("       " + f["detail"])
            r.append("       Confidence : {}%  |  Category: {}".format(
                f["confidence"], f["threat_category"]))
            r.append("       MITRE: " + f["mitre_technique"])
            r.append("       Fix  : " + f["recommendation"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
