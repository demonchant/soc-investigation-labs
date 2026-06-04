"""Digital Forensics Incident Report Generator."""
from datetime import datetime
from collections import defaultdict

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, findings, metadata):
        findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],9))
        by_cat = defaultdict(list)
        for f in findings:
            by_cat[f["category"]].append(f)
        c = sum(1 for f in findings if f["severity"]=="critical")
        h = sum(1 for f in findings if f["severity"]=="high")
        r = []
        r.append("=" * 65)
        r.append("  DIGITAL FORENSICS ANALYSIS REPORT")
        r.append("  Host      : " + metadata.get("host","unknown"))
        r.append("  Collected : " + metadata.get("collection_time",""))
        r.append("  Analyst   : " + metadata.get("collector",""))
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Findings  : " + str(len(findings)) +
                 "  |  " + str(c) + " Critical  |  " + str(h) + " High")
        r.append("=" * 65)

        r.append("\n  FINDING SUMMARY BY CATEGORY\n")
        for cat, cat_findings in sorted(by_cat.items()):
            top = min(SEV_ORDER.get(f["severity"],9) for f in cat_findings)
            sev_name = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"][top] if top <= 4 else "INFO"
            r.append("  [" + sev_name + "] " + cat.upper().replace("_"," ").ljust(22) +
                     ": " + str(len(cat_findings)) + " finding(s)")

        r.append("\n\n  DETAILED FINDINGS\n")
        for i, f in enumerate(findings, 1):
            lbl = SEV_LABEL.get(f["severity"],"[?]")
            r.append("  [" + str(i) + "] " + lbl + " [" + f["category"].upper() + "] " + f["title"])
            r.append("       Detail  : " + f["detail"])
            r.append("       MITRE   : " + f["mitre"])
            if f.get("evidence"):
                for k, v in f["evidence"].items():
                    r.append("       " + str(k).ljust(16) + ": " + str(v)[:80])
            r.append("")
        r.append("=" * 65)
        r.append("\n  RECOMMENDED IMMEDIATE ACTIONS\n")
        r.append("  1. Preserve memory image and disk snapshot before remediation")
        r.append("  2. Isolate host from network immediately")
        r.append("  3. Reset all credentials used on this host")
        r.append("  4. Identify and block all C2 IPs at perimeter firewall")
        r.append("  5. Remove malicious scheduled tasks and registry run keys")
        r.append("  6. Submit file hashes to threat intelligence platforms")
        r.append("  7. Perform lateral movement review for other hosts")
        r.append("  8. Escalate to Incident Response team\n")
        r.append("=" * 65)
        return "\n".join(r)
