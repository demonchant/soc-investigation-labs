from datetime import datetime
from collections import Counter
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, data):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        counts   = Counter(f["severity"] for f in findings)
        n_nodes  = len(data.get("nodes", []))
        n_edges  = len(data.get("edges", []))
        shortest = [f for f in findings if "Attack Path Found" in f["title"]]
        shortest.sort(key=lambda f: len(f["path"]))

        r = []
        r.append("="*68)
        r.append("  ATTACK PATH GRAPH ENGINE — BLOODHOUND-STYLE ANALYSIS")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Graph: {} nodes, {} edges  |  Findings: {}".format(n_nodes, n_edges, len(findings)))
        r.append("  {} Critical  |  {} High  |  {} Medium".format(
            counts.get("critical",0), counts.get("high",0), counts.get("medium",0)))
        r.append("="*68)
        r.append("")
        if shortest:
            r.append("  SHORTEST PATH TO DOMAIN ADMIN: {} hop(s)".format(len(shortest[0]["path"])-1))
            r.append("  " + " -> ".join(shortest[0]["path"]))
            r.append("")
        for i,f in enumerate(findings,1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [{}] {} {}".format(i, lbl, f["title"]))
            r.append("       " + f["detail"])
            r.append("       MITRE: " + f["mitre_technique"])
            r.append("       Fix  : " + f["recommendation"])
            r.append("")
        r.append("="*68)
        return "\n".join(r)
