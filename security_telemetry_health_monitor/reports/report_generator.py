from collections import Counter


def generate_report(findings, source_count):
    counts = Counter(item["severity"] for item in findings)
    lines = [
        "SECURITY TELEMETRY HEALTH REPORT",
        "=" * 42,
        "Sources: {} | Findings: {} | Critical: {} | High: {}".format(
            source_count, len(findings), counts["critical"], counts["high"]
        ),
        "",
    ]
    for item in findings:
        lines.extend([
            "[{}] {}".format(item["severity"].upper(), item["title"]),
            "Source: {} | ATT&CK data source: {}".format(
                item["source"], item["attack_data_source"]
            ),
            "Evidence: {}".format(item["evidence"]),
            "Action: {}".format(item["recommendation"]),
            "",
        ])
    return "\n".join(lines)
