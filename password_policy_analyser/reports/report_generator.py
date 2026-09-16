from datetime import datetime
from collections import defaultdict
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, accounts, policy):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        by_user = defaultdict(list)
        for f in findings: by_user[f["username"]].append(f)
        c = sum(1 for f in findings if f["severity"]=="critical")
        h = sum(1 for f in findings if f["severity"]=="high")
        r = []
        r.append("="*65)
        r.append("  PASSWORD POLICY COMPLIANCE AUDIT REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Accounts  : {}  |  Findings: {}".format(len(accounts), len(findings)))
        r.append("  {} Critical  |  {} High".format(c, h))
        r.append("="*65)
        r.append("")
        for user, ufs in sorted(by_user.items(),
                key=lambda x: min(SEV_ORDER.get(f["severity"],9) for f in x[1])):
            top = min(SEV_ORDER.get(f["severity"],9) for f in ufs)
            tier = ["CRITICAL","HIGH","MEDIUM","LOW"][top] if top <= 3 else "INFO"
            r.append("  [{}] {:<20} — {} issue(s)".format(tier, user, len(ufs)))
        r.append("")
        for i, f in enumerate(findings, 1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} [{}] {}".format(i, lbl, f["username"], f["title"]))
            r.append("       Detail : " + f["detail"])
            r.append("       MITRE  : " + f["mitre_technique"])
            r.append("       Fix    : " + f["recommendation"])
            r.append("")
        r.append("="*65)
        return "\n".join(r)
