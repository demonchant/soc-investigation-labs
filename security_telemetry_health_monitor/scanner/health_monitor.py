class TelemetryHealthMonitor:
    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def analyze(self, sources):
        findings = []
        for source in sources:
            name = source["source"]
            expected = max(source.get("expected_events_per_hour", 0), 1)
            observed = source.get("observed_events_per_hour", 0)
            ratio = observed / expected

            if observed == 0:
                findings.append(self.finding(
                    name, "Telemetry source is silent", "critical", "DS0029",
                    {"expected_events_per_hour": expected, "observed_events_per_hour": observed},
                    "Restore collection and determine when visibility was lost.",
                ))
            elif ratio < 0.25:
                findings.append(self.finding(
                    name, "Severe telemetry volume drop", "high", "DS0029",
                    {"expected_events_per_hour": expected, "observed_events_per_hour": observed},
                    "Inspect source agents, queues, filtering, and ingestion capacity.",
                ))

            delay = source.get("ingestion_delay_seconds", 0)
            if delay > source.get("maximum_delay_seconds", 300):
                findings.append(self.finding(
                    name, "Ingestion delay exceeds service objective", "high", "DS0015",
                    {"delay_seconds": delay},
                    "Check queue depth and scale the ingestion path.",
                ))

            parse_failure = source.get("parse_failure_percent", 0)
            if parse_failure >= 10:
                findings.append(self.finding(
                    name, "Parser failure rate is elevated", "high", "DS0015",
                    {"parse_failure_percent": parse_failure},
                    "Quarantine malformed events and update the parser with regression fixtures.",
                ))

            required = set(source.get("required_fields", []))
            present = set(source.get("fields_present", []))
            missing = sorted(required - present)
            if missing:
                findings.append(self.finding(
                    name, "Required security fields are missing", "high", "DS0015",
                    {"missing_fields": missing},
                    "Correct source mapping before dependent detections are trusted.",
                ))

            clock_skew = abs(source.get("clock_skew_seconds", 0))
            if clock_skew > 120:
                findings.append(self.finding(
                    name, "Source clock skew can break correlation", "medium", "DS0015",
                    {"clock_skew_seconds": clock_skew},
                    "Restore time synchronization and reprocess affected events where possible.",
                ))

            if source.get("retention_days", 0) < source.get("required_retention_days", 30):
                findings.append(self.finding(
                    name, "Retention is below investigation requirement", "medium", "DS0015",
                    {"retention_days": source.get("retention_days")},
                    "Increase searchable retention or archive events in protected storage.",
                ))

        return sorted(
            findings,
            key=lambda item: (-self.SEVERITY_ORDER[item["severity"]], item["source"]),
        )

    @staticmethod
    def finding(source, title, severity, data_source, evidence, recommendation):
        return {
            "source": source,
            "title": title,
            "severity": severity,
            "attack_data_source": data_source,
            "evidence": evidence,
            "recommendation": recommendation,
        }
