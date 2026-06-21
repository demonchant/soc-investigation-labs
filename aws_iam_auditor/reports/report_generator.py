from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        by_entity = Counter(f["entity"] for f in findings)
        total_entities = len(data.get("users",[])) + len(data.get("roles",[])) + len(data.get("policies",[]))
        r = []
        r.append("="*65)
        r.append("  AWS IAM SECURITY AUDIT REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Entities   : {}  |  Findings: {}".format(total_entities, len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium".format(
            counts.get("critical",0), counts.get("high",0), counts.get("medium",0)))
        r.append("="*65)
        r.append("")
        for entity, cnt in sorted(by_entity.items(), key=lambda x: -x[1]):
            ef = [f for f in findings if f["entity"]==entity]
            worst = next((s for s in ["critical","high","medium","low"]
                         if any(f["severity"]==s for f in ef)), "ok")
            r.append("  {:<28}: {} finding(s)  [{}]".format(entity, cnt, worst.upper()))
        r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {}".format(i, lbl, f["entity"], f["title"]))
            r.append("       " + f["detail"])
            r.append("       MITRE: " + f["mitre_technique"])
            r.append("       Fix  : " + f["recommendation"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
