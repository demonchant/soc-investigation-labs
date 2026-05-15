"""
Report Generator — Formats detected alerts into a readable SOC incident report.
"""
from datetime import datetime

SEVERITY_ICON = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]"
}


class ReportGenerator:
    def generate(self, alerts):
        if not alerts:
            return "[OK] No security incidents detected in this log batch."

        report = []
        report.append("=" * 55)
        report.append("  SECURITY INCIDENT REPORT - SOC AUTOMATION ENGINE")
        report.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append("=" * 55)
        report.append(f"\n  Total Alerts: {len(alerts)}\n")

        for i, alert in enumerate(alerts, 1):
            sev = alert.get("severity", "medium")
            icon = SEVERITY_ICON.get(sev, "[UNKNOWN]")
            report.append(f"  [{i}] {icon} {alert['alert']}")
            report.append(f"      MITRE        : {alert.get('mitre_technique', 'N/A')}")
            report.append(f"      Source IP    : {alert.get('source_ip', 'N/A')}")

            if "attempts" in alert:
                report.append(f"      Attempts     : {alert['attempts']}")
                report.append(f"      First Seen   : {alert.get('first_seen', 'N/A')}")
                report.append(f"      Last Seen    : {alert.get('last_seen', 'N/A')}")

            if "hosts_accessed" in alert:
                report.append(f"      Hosts Hit    : {', '.join(alert['hosts_accessed'])}")

            if "process" in alert:
                report.append(f"      Process      : {alert['process']}")
                report.append(f"      User         : {alert.get('user', 'N/A')}")

            if alert.get("description"):
                report.append(f"      Description  : {alert['description']}")

            report.append("")

        report.append("=" * 55)
        return "\n".join(report)
