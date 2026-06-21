import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "coverage": "Detection Coverage Gap - MITRE ATT&CK Matrix",
    "datasrc":  "Data Source Health - Detection Engineering Prerequisite",
    "stale":    "Detection Engineering - Rule Maintenance",
    "tactic":   "Tactic-Level Coverage Gap",
}

# Full kill-chain tactics with their critical, must-cover techniques
ATTACK_MATRIX = {
    "Reconnaissance":        ["T1595", "T1592", "T1589"],
    "Resource Development":  ["T1583", "T1586", "T1588"],
    "Initial Access":        ["T1566", "T1190", "T1133", "T1078"],
    "Execution":             ["T1059", "T1203", "T1047", "T1053"],
    "Persistence":           ["T1547", "T1053.005", "T1098", "T1136"],
    "Privilege Escalation":  ["T1548", "T1055", "T1068", "T1078.004"],
    "Defense Evasion":       ["T1070", "T1027", "T1036", "T1562", "T1140"],
    "Credential Access":     ["T1003", "T1110", "T1558", "T1552"],
    "Discovery":             ["T1082", "T1087", "T1046", "T1018", "T1482"],
    "Lateral Movement":      ["T1021", "T1550", "T1080"],
    "Collection":            ["T1074", "T1056", "T1113", "T1005"],
    "Command and Control":   ["T1071", "T1573", "T1090", "T1008"],
    "Exfiltration":          ["T1048", "T1567", "T1029"],
    "Impact":                ["T1486", "T1490", "T1485", "T1489"],
}

REQUIRED_DATA_SOURCES = {
    "windows_security_eventlog": ["Initial Access", "Privilege Escalation", "Credential Access", "Lateral Movement"],
    "sysmon_process_creation":   ["Execution", "Defense Evasion", "Persistence"],
    "edr_telemetry":             ["Privilege Escalation", "Defense Evasion", "Collection"],
    "network_flow_netflow":      ["Command and Control", "Exfiltration", "Lateral Movement"],
    "dns_query_logs":            ["Command and Control", "Exfiltration", "Reconnaissance"],
    "cloud_audit_logs":          ["Initial Access", "Persistence", "Privilege Escalation"],
    "firewall_proxy_logs":       ["Command and Control", "Exfiltration", "Initial Access"],
    "auth_idp_logs":             ["Initial Access", "Credential Access", "Lateral Movement"],
}

STALE_RULE_THRESHOLD_DAYS = 365

class MaturityScorecard:
    def __init__(self): self.findings = []

    def assess_all(self, data):
        deployed_techniques = self._extract_deployed_techniques(data)
        self._score_tactic_coverage(deployed_techniques)
        self._check_data_source_health(data)
        self._check_stale_rules(data)
        self._compute_program_score(deployed_techniques, data)
        return self.findings

    def _f(self, title, sev, detail, mitre, rec, score_contrib=0):
        self.findings.append({"title": title, "severity": sev, "detail": detail,
            "mitre_technique": mitre, "recommendation": rec, "score_contribution": score_contrib})

    def _extract_deployed_techniques(self, data):
        techniques = set()
        for rule in data.get("deployed_rules", []):
            techniques.add(rule.get("mitre_technique", "").split(".")[0])
            full = rule.get("mitre_technique", "")
            if full: techniques.add(full)
        return techniques

    def _technique_covered(self, technique, deployed):
        # match exact or parent technique (e.g. T1053.005 satisfied by T1053 rule)
        base = technique.split(".")[0]
        return technique in deployed or base in deployed

    def _score_tactic_coverage(self, deployed):
        tactic_scores = {}
        for tactic, techniques in ATTACK_MATRIX.items():
            covered = [t for t in techniques if self._technique_covered(t, deployed)]
            pct = len(covered) / len(techniques) * 100
            tactic_scores[tactic] = pct
            missing = [t for t in techniques if t not in covered]

            if pct == 0:
                self._f("ZERO Coverage: {} Tactic".format(tactic), "critical",
                    "No detection rules cover ANY technique in '{}'. Missing: {}.".format(
                        tactic, ", ".join(missing)),
                    MITRE["tactic"],
                    "This is a complete blind spot. An attacker operating purely in this "
                    "tactic generates zero alerts. Prioritize rule development here first.",
                    -30)
            elif pct < 40:
                self._f("Low Coverage: {} Tactic ({:.0f}%)".format(tactic, pct), "high",
                    "Only {}/{} techniques covered in '{}'. Missing: {}.".format(
                        len(covered), len(techniques), tactic, ", ".join(missing)),
                    MITRE["coverage"],
                    "Significant gap. Add detections for: {}.".format(", ".join(missing[:3])),
                    -15)
            elif pct < 75:
                self._f("Partial Coverage: {} Tactic ({:.0f}%)".format(tactic, pct), "medium",
                    "{}/{} techniques covered. Missing: {}.".format(
                        len(covered), len(techniques), ", ".join(missing)),
                    MITRE["coverage"],
                    "Acceptable but improvable. Close remaining gaps in next quarter.", -5)
        return tactic_scores

    def _check_data_source_health(self, data):
        sources = {s["name"]: s for s in data.get("data_sources", [])}
        for required_src, supported_tactics in REQUIRED_DATA_SOURCES.items():
            src = sources.get(required_src)
            if not src:
                self._f("Missing Data Source: {}".format(required_src), "critical",
                    "No ingestion configured for '{}', which is required for detecting: {}.".format(
                        required_src, ", ".join(supported_tactics)),
                    MITRE["datasrc"],
                    "Onboard this log source. Without it, all rules depending on it are "
                    "non-functional regardless of how well-written they are.", -20)
                continue

            if not src.get("active", False):
                self._f("Data Source Inactive: {}".format(required_src), "critical",
                    "'{}' is configured but NOT actively ingesting (last seen: {}).".format(
                        required_src, src.get("last_event_received", "never")),
                    MITRE["datasrc"],
                    "Investigate ingestion pipeline failure. All dependent detections are "
                    "currently blind.", -20)
                continue

            retention = src.get("retention_days", 0)
            if retention < 90:
                self._f("Short Retention: {} ({} days)".format(required_src, retention), "medium",
                    "'{}' retains only {} days — insufficient for detecting slow/dwelling "
                    "threats or supporting retrospective hunts.".format(required_src, retention),
                    MITRE["datasrc"],
                    "Extend retention to 90+ days minimum (365 for Tier-0 sources) per "
                    "incident response and compliance requirements.", -5)

            latency = src.get("ingestion_latency_minutes", 0)
            if latency > 15:
                self._f("High Ingestion Latency: {} ({} min)".format(required_src, latency), "medium",
                    "'{}' has {}-minute average ingestion delay — detection-to-alert time "
                    "is correspondingly delayed during active incidents.".format(
                        required_src, latency),
                    MITRE["datasrc"],
                    "Investigate pipeline bottleneck (collector sizing, parsing overhead, "
                    "network path to SIEM).", -5)

    def _check_stale_rules(self, data):
        for rule in data.get("deployed_rules", []):
            days_since_review = rule.get("days_since_last_review", 0)
            if days_since_review > STALE_RULE_THRESHOLD_DAYS:
                self._f("Stale Rule: {} ({} days unreviewed)".format(
                    rule.get("rule_id","?"), days_since_review), "low",
                    "Rule '{}' (covers {}) has not been reviewed in {} days. Threat "
                    "landscape and environment likely changed since.".format(
                        rule.get("rule_id","?"), rule.get("mitre_technique","?"), days_since_review),
                    MITRE["stale"],
                    "Schedule quarterly rule review cycle. Validate against current TTPs "
                    "and re-test false positive rate.", -2)

    def _compute_program_score(self, deployed, data):
        total_techniques = sum(len(v) for v in ATTACK_MATRIX.values())
        covered = sum(1 for techs in ATTACK_MATRIX.values() for t in techs
                      if self._technique_covered(t, deployed))
        coverage_pct = covered / total_techniques * 100

        active_sources = sum(1 for s in data.get("data_sources", []) if s.get("active"))
        required_sources = len(REQUIRED_DATA_SOURCES)
        source_health_pct = min(active_sources / required_sources * 100, 100)

        composite = (coverage_pct * 0.6) + (source_health_pct * 0.4)
        maturity_level = (
            "OPTIMIZED (Tier 4)" if composite >= 85 else
            "MANAGED (Tier 3)"   if composite >= 65 else
            "DEFINED (Tier 2)"   if composite >= 40 else
            "INITIAL (Tier 1)"
        )

        self._f("PROGRAM MATURITY SCORE: {:.1f}/100 — {}".format(composite, maturity_level),
            "critical" if composite < 40 else "high" if composite < 65 else "low",
            "ATT&CK technique coverage: {:.1f}% ({}/{}). Data source health: {:.1f}% "
            "({}/{} required sources active). Composite weighted score reflects both "
            "rule coverage AND the data infrastructure required to support it.".format(
                coverage_pct, covered, total_techniques,
                source_health_pct, active_sources, required_sources),
            "Composite Program Score",
            "Maturity roadmap: {}".format(
                "Focus on data source onboarding — coverage gains are meaningless without "
                "ingestion." if source_health_pct < coverage_pct else
                "Focus on rule development — your data foundation can support significantly "
                "more detection coverage than currently deployed."),
            composite)
