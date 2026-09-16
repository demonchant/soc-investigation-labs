from datetime import datetime
from collections import Counter, defaultdict
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        by_inc   = defaultdict(list)
        for f in findings: by_inc[f["incident_id"]].append(f)
        r = []
        r.append("="*68)
        r.append("  SOAR PLAYBOOK ENGINE — ORCHESTRATION REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Incidents : {}  |  Actions Tracked: {}".format(
            len(data.get("incidents",[])), len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low".format(
            counts.get("critical",0), counts.get("high",0),
            counts.get("medium",0),   counts.get("low",0)))
        r.append("="*68)
        r.append("")
        for inc_id, inc_findings in by_inc.items():
            pb = inc_findings[0]["playbook"] if inc_findings else "?"
            r.append("  INCIDENT: {}  |  PLAYBOOK: {}".format(inc_id, pb))
            r.append("  " + "-"*54)
            for f in inc_findings:
                lbl = SEV_LABEL.get(f["severity"],"[?]")
                r.append("  {} {}".format(lbl, f["title"]))
                r.append("       " + f["detail"])
                r.append("       Action: " + f["recommendation"])
                r.append("")
        r.append("="*68)
        return "\n".join(r)
