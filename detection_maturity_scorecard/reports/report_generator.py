from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        program = next((f for f in findings if "PROGRAM MATURITY" in f["title"]), None)
        rest = sorted([f for f in findings if f is not program],
                      key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts = Counter(f["severity"] for f in rest)
        n_rules = len(data.get("deployed_rules", []))
        n_sources = len(data.get("data_sources", []))

        r = []
        r.append("="*68)
        r.append("  DETECTION MATURITY SCORECARD — PROGRAM ASSESSMENT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Deployed Rules: {}  |  Data Sources: {}  |  Gaps Found: {}".format(
            n_rules, n_sources, len(rest)))
        r.append("="*68)
        r.append("")
        if program:
            r.append("  " + program["title"])
            r.append("  " + program["detail"])
            r.append("  >> " + program["recommendation"])
            r.append("")
        r.append("  {} Critical  |  {} High  |  {} Medium  |  {} Low".format(
            counts.get("critical",0), counts.get("high",0),
            counts.get("medium",0),   counts.get("low",0)))
        r.append("="*68)
        r.append("")
        r.append("  PRIORITIZED GAP REMEDIATION (worst impact first):")
        r.append("")
        for i,f in enumerate(rest,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} {}".format(i, lbl, f["title"]))
            r.append("       " + f["detail"])
            r.append("       Fix: " + f["recommendation"])
            r.append("")
        r.append("="*68)
        return "\n".join(r)
