"""SOC Metrics Report Generator — formatted KPI summary."""
from datetime import datetime

def _bar(pct, width=20):
    filled = round(pct / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "] " + str(pct) + "%"

class ReportGenerator:
    def generate(self, m):
        r = []
        r.append("=" * 65)
        r.append("  SOC PERFORMANCE METRICS — MONTHLY KPI REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Period    : " + m["period"])
        r.append("=" * 65)

        r.append("\n  ALERT VOLUME\n")
        r.append("  Total Alerts      : " + str(m["total_alerts"]))
        for sev, cnt in sorted(m["alerts_by_severity"].items()):
            r.append("    " + sev.upper().ljust(10) + ": " + str(cnt))

        r.append("\n  DETECTION QUALITY\n")
        r.append("  True Positives    : " + str(m["true_positives"]) + " (" + str(m["tp_rate_pct"]) + "%)")
        r.append("  False Positives   : " + str(m["false_positives"]) + " (" + str(m["fp_rate_pct"]) + "%)")
        r.append("  " + _bar(m["tp_rate_pct"]) + " <- TP Rate (higher = better)")

        r.append("\n  RESPONSE TIME KPIs\n")
        r.append("  MTTA (Mean Time to Acknowledge) : " + str(m["mtta_mins"]) + " min")
        for sev, mins in m.get("mtta_by_severity",{}).items():
            r.append("    " + sev.upper().ljust(10) + ": " + str(mins) + " min")
        r.append("  MTTR (Mean Time to Resolve)     : " + str(m["mttr_alert_mins"]) + " min (alerts)")
        r.append("  MTTC (Mean Time to Contain)     : " + str(m["mttc_hours"]) + " hr (incidents)")
        r.append("  MTTI (Mean Time to Resolve)     : " + str(m["mtti_hours"]) + " hr (incidents)")

        r.append("\n  SLA COMPLIANCE\n")
        r.append("  Compliance Rate   : " + _bar(m["sla_compliance_pct"]))
        if m["sla_breaches"]:
            r.append("  Breaches (" + str(len(m["sla_breaches"])) + "):")
            for b in m["sla_breaches"]:
                r.append("    " + b["alert_id"] + " [" + b["severity"].upper() + "]"
                         + " target=" + str(b["target_mins"]) + "min"
                         + " actual=" + str(b["actual_mins"]) + "min"
                         + " overrun=+" + str(b["overrun_mins"]) + "min")

        r.append("\n  ANALYST WORKLOAD\n")
        for analyst, stats in sorted(m["analyst_workload"].items()):
            tp_pct = round(stats["tp"] / stats["total"] * 100) if stats["total"] else 0
            r.append("  " + analyst.ljust(12) + ": " + str(stats["total"]).ljust(4)
                     + " alerts | TP=" + str(stats["tp"]) + " FP=" + str(stats["fp"])
                     + " (" + str(tp_pct) + "% TP rate)")

        r.append("\n  INCIDENT METRICS\n")
        r.append("  Total Incidents   : " + str(m["total_incidents"]))
        r.append("  MTTC              : " + str(m["mttc_hours"]) + " hr")
        r.append("  MTTI              : " + str(m["mtti_hours"]) + " hr")

        r.append("\n" + "=" * 65)
        return "\n".join(r)
