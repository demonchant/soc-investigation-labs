"""Exchange Security Report Generator."""
from datetime import datetime

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABEL = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}


class ReportGenerator:
    def generate(self, alerts):
        if not alerts:
            return "[OK] No exchange security events detected."
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"], 9))
        c = sum(1 for a in alerts if a["severity"] == "critical")
        h = sum(1 for a in alerts if a["severity"] == "high")
        r = []
        r.append("=" * 65)
        r.append("  CRYPTO EXCHANGE SECURITY INCIDENT REPORT")
        r.append("  Generated   : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Total Alerts: " + str(len(alerts)) + "   |   " + str(c) + " Critical  |  " + str(h) + " High")
        r.append("=" * 65)
        for i, a in enumerate(alerts, 1):
            lbl = SEV_LABEL.get(a["severity"], "[?]")
            r.append("")
            r.append("  [" + str(i) + "] " + lbl + " " + a["title"])
            r.append("       User ID     : " + str(a["user_id"]))
            r.append("       MITRE       : " + a["mitre_technique"])
            if a.get("regulation"):
                r.append("       Regulation  : " + a["regulation"])
            for k, v in a.get("evidence", {}).items():
                r.append("       " + str(k).ljust(18) + ": " + str(v))
        r.append("")
        r.append("=" * 65)
        return "\n".join(r)
