"""UEBA Insider Threat Report Generator."""
from datetime import datetime
from collections import defaultdict

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, alerts, profiles):
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"],9))
        by_user = defaultdict(list)
        for a in alerts:
            by_user[a["user"]].append(a)

        r = []
        r.append("="*65)
        r.append("  UEBA — USER BEHAVIOUR ANALYTICS REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Users Profiled : " + str(len(profiles)))
        c = sum(1 for a in alerts if a["severity"]=="critical")
        h = sum(1 for a in alerts if a["severity"]=="high")
        r.append("  Alerts : " + str(len(alerts)) + "  |  " + str(c) + " Critical  |  " + str(h) + " High")
        r.append("="*65)

        r.append("\n  USER RISK SUMMARY\n")
        for user, user_alerts in sorted(by_user.items(), key=lambda x: -len(x[1])):
            top_sev = min(SEV_ORDER.get(a["severity"],9) for a in user_alerts)
            sev_name = ["CRITICAL","HIGH","MEDIUM","LOW"][top_sev] if top_sev < 4 else "INFO"
            r.append("  [" + sev_name + "] " + user + " — " + str(len(user_alerts)) + " alert(s)")

        r.append("\n\n  DETAILED ALERTS\n")
        for i, a in enumerate(alerts, 1):
            lbl = SEV_LABEL.get(a["severity"],"[?]")
            r.append("  [" + str(i) + "] " + lbl + " " + a["title"])
            r.append("       User   : " + a["user"])
            r.append("       MITRE  : " + a["mitre_technique"])
            for k, v in a.get("evidence",{}).items():
                r.append("       " + str(k).ljust(20) + ": " + str(v))
            r.append("")
        r.append("="*65)
        return "\n".join(r)
