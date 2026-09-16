from datetime import datetime
from collections import Counter

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, assets):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts = Counter(f["severity"] for f in findings)
        compliant = sum(1 for a in assets if a.get("patch_compliance_pct",0)==100)
        avg = sum(a.get("patch_compliance_pct",0) for a in assets)/len(assets) if assets else 0
        r = []
        r.append("="*65)
        r.append("  PATCH COMPLIANCE TRACKER REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Assets: {}  |  Fully Compliant: {}  |  Avg: {:.1f}%".format(len(assets),compliant,avg))
        r.append("  {} Critical  |  {} High".format(counts.get("critical",0),counts.get("high",0)))
        r.append("="*65)
        r.append("")
        for a in sorted(assets, key=lambda x: x.get("patch_compliance_pct",100)):
            pct = a.get("patch_compliance_pct",0)
            bar = "#"*(pct//10) + "-"*(10-pct//10)
            inet = " [INET]" if a.get("internet_facing") else ""
            expl = " [EXPLOITED]" if a.get("known_exploited_missing") else ""
            r.append("  {:<20} [{}] {:3d}%  {}{}{}".format(a["hostname"],bar,pct,a["criticality"].upper(),inet,expl))
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {} — {}".format(i,lbl,f["asset_id"],f["hostname"],f["title"]))
            r.append("       " + f["detail"])
            r.append("       " + f["mitre_technique"])
            if f.get("days_overdue",0)>0:
                r.append("       Overrun: +{} days past SLA".format(f["days_overdue"]))
            r.append("")
        r.append("="*65)
        return "\n".join(r)
