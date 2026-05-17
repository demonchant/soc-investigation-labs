"""
Report Generator — Produces a formatted AWS security incident report.
"""
from datetime import datetime
from alerts.alert_manager import get_alerts

ICONS = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}

REMEDIATION = {
    "Root Account Login Detected": "Immediately rotate root credentials. Enable MFA. Review CloudTrail for post-compromise actions.",
    "Root Login Without MFA": "Enable MFA on root account immediately. Consider AWS Organizations SCP to restrict root usage.",
    "New IAM Access Key Created": "Verify with the key owner. If unauthorised, deactivate immediately via IAM console.",
    "IAM Privilege Escalation Attempt": "Review attached policy. Engage incident response if unauthorized. Run IAM Access Analyser.",
    "API Activity from High-Risk Region": "Review request context. Consider SCPs to block API calls from high-risk regions.",
    "New IAM User Created": "Confirm with admin team. Apply principle of least privilege to new account.",
    "Console Login Failure": "Monitor for repeated failures. Consider enabling GuardDuty for automated alerting.",
    "Security Group Modified": "Review the modified rule. Ensure no overly permissive ingress (0.0.0.0/0) was added."
}


class ReportGenerator:
    def generate(self):
        alerts = get_alerts()

        if not alerts:
            return "[OK] No IAM security events detected in this log batch."

        report = []
        report.append("=" * 60)
        report.append("  AWS IAM SECURITY INCIDENT REPORT")
        report.append(f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"  Total Alerts : {len(alerts)}")
        report.append("=" * 60)

        critical = [a for a in alerts if a["severity"] == "critical"]
        high = [a for a in alerts if a["severity"] == "high"]
        medium = [a for a in alerts if a["severity"] == "medium"]
        low = [a for a in alerts if a["severity"] == "low"]

        report.append(f"\n  Summary: {len(critical)} Critical | {len(high)} High | {len(medium)} Medium | {len(low)} Low\n")

        for i, a in enumerate(alerts, 1):
            icon = ICONS.get(a["severity"], "[?]")
            report.append(f"  [{i}] {icon} {a['title']}")
            report.append(f"       MITRE          : {a.get('mitre_technique', 'N/A')}")
            report.append(f"       User           : {a.get('user', 'N/A')}")
            report.append(f"       Event          : {a.get('event', 'N/A')}")
            report.append(f"       Source IP      : {a.get('source_ip', 'N/A')}")
            report.append(f"       Region         : {a.get('region', 'N/A')}")
            if a.get("mfa_used") is not None:
                report.append(f"       MFA Used       : {a['mfa_used']}")
            report.append(f"       Time           : {a.get('time', 'N/A')}")
            rem = REMEDIATION.get(a["title"], "Review and investigate this event immediately.")
            report.append(f"       Remediation    : {rem}")
            report.append("")

        report.append("=" * 60)
        return "\n".join(report)
