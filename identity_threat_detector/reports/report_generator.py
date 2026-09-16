from collections import Counter


def generate_report(findings):
    counts = Counter(item["severity"] for item in findings)
    lines = [
        "IDENTITY THREAT DETECTION REPORT",
        "=" * 42,
        "Findings: {} | Critical: {} | High: {}".format(
            len(findings), counts["critical"], counts["high"]
        ),
        "",
    ]
    for finding in findings:
        lines.extend([
            "[{}] {}".format(finding["severity"].upper(), finding["title"]),
            "User: {} | MITRE: {}".format(finding["user"], finding["mitre_technique"]),
            "Evidence: {}".format(finding["evidence"]),
            "Response: {}".format(finding["recommendation"]),
            "",
        ])
    return "\n".join(lines)
