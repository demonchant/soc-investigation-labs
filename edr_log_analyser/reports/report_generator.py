"""EDR Incident Report Generator."""
from datetime import datetime

SEV_LABEL = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}


class ReportGenerator:
    def generate(self, alerts, chains):
        r = []
        r.append("=" * 65)
        r.append("  ENDPOINT DETECTION & RESPONSE — INCIDENT REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        c = sum(1 for a in alerts if a["severity"] == "critical")
        h = sum(1 for a in alerts if a["severity"] == "high")
        r.append("  Alerts: " + str(len(alerts)) + "   |   " + str(c) + " Critical  |  " + str(h) + " High")
        r.append("  Incident Chains Detected: " + str(len(chains)))
        r.append("=" * 65)

        if chains:
            r.append("\n  INCIDENT CHAINS\n")
            for ch in chains:
                r.append("  [" + ch["verdict"] + "] Host: " + ch["host"])
                r.append("    Alerts       : " + str(ch["alert_count"]))
                r.append("    Max Score    : " + str(ch["max_score"]) + "/100")
                r.append("    Techniques   : " + ", ".join(ch["techniques"]))
                r.append("")

        r.append("  INDIVIDUAL ALERTS\n")
        for i, a in enumerate(alerts, 1):
            lbl = SEV_LABEL.get(a["severity"], "[?]")
            r.append("  [" + str(i) + "] " + lbl + " " + a["title"])
            r.append("       Host       : " + str(a.get("host","")))
            r.append("       User       : " + str(a.get("user","")))
            r.append("       MITRE      : " + a["mitre_technique"])
            r.append("       Score      : " + str(a.get("triage_score",0)) + "/100")
            for k, v in a.get("evidence",{}).items():
                r.append("       " + str(k).ljust(14) + ": " + str(v))
            r.append("")

        r.append("=" * 65)
        return "\n".join(r)
