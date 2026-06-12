from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, containers):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        by_svc   = Counter(f["service"] for f in findings)
        r = []
        r.append("="*65)
        r.append("  CONTAINER SECURITY SCAN REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Containers : {}  |  Findings: {}".format(len(containers),len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium".format(
            counts.get("critical",0),counts.get("high",0),counts.get("medium",0)))
        r.append("="*65)
        r.append("")
        for svc, cnt in sorted(by_svc.items(), key=lambda x: -x[1]):
            sf = [f for f in findings if f["service"]==svc]
            worst = next((s for s in ["critical","high","medium","low"] if any(f["severity"]==s for f in sf)),"ok")
            r.append("  {:<22}: {} finding(s)  [{}]".format(svc,cnt,worst.upper()))
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {}".format(i,lbl,f["service"],f["title"]))
            r.append("       " + f["detail"])
            r.append("       MITRE: " + f["mitre_technique"])
            r.append("       Fix  : " + f["recommendation"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
