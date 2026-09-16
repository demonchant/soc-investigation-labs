from collections import Counter


def generate_report(findings):
    counts = Counter(item["severity"] for item in findings)
    lines = [
        "SAAS ACCOUNT TAKEOVER REPORT",
        "=" * 42,
        "Findings: {} | Critical: {} | High: {}".format(
            len(findings), counts["critical"], counts["high"]
        ),
        "",
    ]
    for item in findings:
        lines.extend([
            "[{}] {}".format(item["severity"].upper(), item["title"]),
            "User: {} | Score: {} | MITRE: {}".format(
                item["user"], item["risk_score"], item["mitre_technique"]
            ),
            "Action: {}".format(item["recommendation"]),
            "",
        ])
    return "\n".join(lines)
