from datetime import datetime
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]"}

class ReportGenerator:
    def generate(self, alerts):
        r = []
        r.append("="*65)
        r.append("  RANSOMWARE BEHAVIOUR DETECTION REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Alerts    : {}  |  ALL CRITICAL — IMMEDIATE ACTION REQUIRED".format(len(alerts)))
        r.append("="*65)
        r.append("")
        r.append("  IMMEDIATE ACTIONS:")
        r.append("  1. ISOLATE all affected hosts from network NOW")
        r.append("  2. DO NOT reboot — preserve memory evidence")
        r.append("  3. Block C2 IPs at perimeter firewall")
        r.append("  4. Notify CISO and legal team immediately")
        r.append("  5. Engage backup/recovery team")
        r.append("")
        for i,a in enumerate(alerts,1):
            r.append("  [{}] [CRITICAL] {}".format(i,a["title"]))
            r.append("       Host   : " + a["host"])
            r.append("       MITRE  : " + a["mitre_technique"])
            for k,v in a.get("evidence",{}).items():
                r.append("       {:<22}: {}".format(str(k), str(v)[:70]))
            r.append("")
        r.append("="*65)
        return "\n".join(r)
