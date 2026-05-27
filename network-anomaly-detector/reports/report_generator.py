"""Report Generator - Network anomaly incident report."""
from datetime import datetime

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABEL = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}

class ReportGenerator:
    def generate(self, alerts, profiles):
        if not alerts:
            return "[OK] No network anomalies detected."
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"], 9))
        c = sum(1 for a in alerts if a["severity"] == "critical")
        h = sum(1 for a in alerts if a["severity"] == "high")
        m = sum(1 for a in alerts if a["severity"] == "medium")
        r = []
        r.append("=" * 62)
        r.append("  NETWORK ANOMALY DETECTION REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Hosts Profiled: " + str(len(profiles)) + "  |  Alerts: " + str(len(alerts)))
        r.append("=" * 62)
        r.append("")
        r.append("  " + str(c) + " Critical  |  " + str(h) + " High  |  " + str(m) + " Medium")
        r.append("")
        for i, a in enumerate(alerts, 1):
            lbl = SEV_LABEL.get(a["severity"], "[?]")
            r.append("  [" + str(i) + "] " + lbl + " " + a["title"])
            r.append("       Source IP  : " + a["src_ip"])
            r.append("       MITRE      : " + a["mitre_technique"])
            for k, v in a.get("evidence", {}).items():
                r.append("       " + str(k).ljust(14) + ": " + str(v))
            r.append("")
        r.append("=" * 62)
        return "\n".join(r)
