from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts = Counter(f["severity"] for f in findings)
        areas  = Counter(f["area"] for f in findings)
        r = []
        r.append("="*65)
        r.append("  ZERO TRUST ARCHITECTURE AUDIT REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Findings  : {}  |  {} Critical  |  {} High".format(
            len(findings),counts.get("critical",0),counts.get("high",0)))
        r.append("="*65)
        r.append("")
        for area, cnt in sorted(areas.items()):
            af = [f for f in findings if f["area"]==area]
            worst = next((s for s in ["critical","high","medium","low"] if any(f["severity"]==s for f in af)),"ok")
            r.append("  {:<18}: {} finding(s)  [worst: {}]".format(area.upper(),cnt,worst.upper()))
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {}".format(i,lbl,f["area"].upper(),f["title"]))
            r.append("       Detail    : " + f["detail"])
            r.append("       ZT Pillar : " + f["zt_principle"][:80])
            r.append("       MITRE     : " + f["mitre_technique"])
            r.append("       Fix       : " + f["recommendation"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
