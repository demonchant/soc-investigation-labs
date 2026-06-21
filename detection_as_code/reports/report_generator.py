from datetime import datetime
from collections import Counter, defaultdict
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}
STAGE_ORDER = {"LINT":0,"TEST":1,"GATE":2}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: (STAGE_ORDER.get(f["stage"],9), SEV_ORDER.get(f["severity"],9)))
        counts   = Counter(f["severity"] for f in findings)
        approved = sum(1 for f in findings if f["stage"]=="GATE" and "APPROVED" in f["title"])
        blocked  = sum(1 for f in findings if f["stage"]=="GATE" and "BLOCKED" in f["title"])
        n_rules  = len(data.get("rules", []))

        r = []
        r.append("="*68)
        r.append("  DETECTION-AS-CODE PIPELINE — CI/CD REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Rules Processed: {}  |  Pipeline Findings: {}".format(n_rules, len(findings)))
        r.append("  Deployment: {} APPROVED  |  {} BLOCKED".format(approved, blocked))
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low".format(
            counts.get("critical",0), counts.get("high",0),
            counts.get("medium",0),   counts.get("low",0)))
        r.append("="*68)
        r.append("")
        by_stage = defaultdict(list)
        for f in findings: by_stage[f["stage"]].append(f)
        for stage in ["LINT","TEST","GATE"]:
            stage_findings = by_stage.get(stage, [])
            if not stage_findings: continue
            r.append("  STAGE: {}".format(stage))
            r.append("  " + "-"*40)
            for f in stage_findings:
                lbl = SEV_LABEL.get(f["severity"],"[?]")
                r.append("  {} [{}] {}".format(lbl, f["rule_id"], f["title"]))
                r.append("       " + f["detail"])
                r.append("       Next: " + f["recommendation"])
                r.append("")
        r.append("="*68)
        return "\n".join(r)
