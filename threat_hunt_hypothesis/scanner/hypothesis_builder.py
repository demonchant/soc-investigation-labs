"""
Threat Hunt Hypothesis Builder
Formalizes hunting hypotheses into structured, repeatable documents:
MITRE mapping, data source requirements, confirmation/refutation criteria,
quality scoring, staleness checks, and coverage gap analysis.
"""
import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "quality":  "Detection Engineering - Hunt Hypothesis Quality",
    "gap":      "Detection Engineering - Coverage Gap Identification",
    "datasrc":  "Detection Engineering - Data Source Dependency",
    "stale":    "Threat Hunting - Hypothesis Staleness",
    "overlap":  "Threat Hunting - Redundant Hypothesis",
}

REQUIRED_DATA_SOURCES = {
    "T1059": ["process_creation_logs","sysmon_event_1","edr_telemetry"],
    "T1055": ["edr_telemetry","sysmon_event_8","memory_forensics"],
    "T1071": ["network_flow","proxy_logs","dns_logs"],
    "T1003": ["edr_telemetry","windows_security_eventlog","memory_forensics"],
    "T1021": ["windows_security_eventlog","network_flow","sysmon_event_3"],
    "T1078": ["auth_logs","vpn_logs","cloud_audit_logs"],
    "T1110": ["auth_logs","web_access_logs"],
    "T1566": ["email_gateway_logs","web_proxy_logs","edr_telemetry"],
    "T1486": ["file_system_events","edr_telemetry","windows_security_eventlog"],
    "T1558": ["windows_security_eventlog","kerberos_logs"],
}

QUALITY_CRITERIA = [
    ("mitre_technique",        15, "MITRE ATT&CK technique mapped"),
    ("data_sources",           15, "Required data sources identified"),
    ("confirmation_criteria",  20, "Confirmation criteria defined"),
    ("refutation_criteria",    15, "Refutation criteria defined"),
    ("priority",               10, "Hunt priority assigned"),
    ("expected_artifacts",     15, "Expected artifacts documented"),
    ("false_positive_notes",   10, "False positive considerations noted"),
]

STALE_DAYS = 90

class HypothesisBuilder:
    def __init__(self): self.findings = []

    def analyze_all(self, data):
        hypotheses = data.get("hypotheses", [])
        available  = set(data.get("available_data_sources", []))
        for hyp in hypotheses:
            self._score_quality(hyp)
            self._check_data_availability(hyp, available)
            self._check_staleness(hyp)
        self._detect_duplicates(hypotheses)
        self._coverage_gaps(hypotheses, data.get("threat_intel_techniques", []))
        return self.findings

    def _f(self, hid, title, sev, detail, mitre, rec):
        self.findings.append({"hypothesis_id": hid, "title": title,
            "severity": sev, "detail": detail,
            "mitre_technique": mitre, "recommendation": rec})

    def _score_quality(self, hyp):
        hid   = hyp.get("hypothesis_id","?")
        score = 0
        missing = []
        for field, pts, desc in QUALITY_CRITERIA:
            val = hyp.get(field)
            if val and val != [] and val != "":
                score += pts
            else:
                missing.append(desc)
        grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=60 else "D" if score>=40 else "F"
        sev   = "critical" if grade=="F" else "high" if grade=="D" else "medium" if grade=="C" else "low"
        if missing:
            self._f(hid, "Hypothesis Quality: Grade {} ({}/100) — {}".format(grade, score, hid), sev,
                "Hypothesis '{}' scored {}/100. Missing: {}.".format(
                    hyp.get("title","?"), score, "; ".join(missing)),
                MITRE["quality"],
                "Complete missing fields before executing. A fully documented hypothesis "
                "is reproducible across analysts and auditable after the hunt.")
        else:
            self._f(hid, "Hypothesis Quality: Grade A ({}/100) — {}".format(score, hid), "low",
                "Hypothesis '{}' is fully documented and ready for execution.".format(
                    hyp.get("title","?")),
                MITRE["quality"], "Proceed with hunt execution. Document findings in hypothesis record.")

    def _check_data_availability(self, hyp, available):
        hid      = hyp.get("hypothesis_id","?")
        tech     = hyp.get("mitre_technique","").split(".")[0]
        required = set(REQUIRED_DATA_SOURCES.get(tech, []))
        missing  = required - available
        if missing:
            self._f(hid, "Missing Data Sources for {} ({})".format(hid, tech), "high",
                "Hunt '{}' requires data sources not available: {}. "
                "Hunt coverage will be incomplete.".format(
                    hyp.get("title","?"), ", ".join(sorted(missing))),
                MITRE["datasrc"],
                "Onboard missing sources before executing, or document that coverage is "
                "partial and specify which hosts/techniques are excluded from scope.")

    def _check_staleness(self, hyp):
        hid      = hyp.get("hypothesis_id","?")
        last_run = hyp.get("last_executed_days_ago", 0)
        status   = hyp.get("status","pending").lower()
        if status == "pending" and last_run == 0:
            return
        if last_run > STALE_DAYS:
            self._f(hid, "Stale Hypothesis: {} ({} days since last run)".format(hid, last_run), "medium",
                "Hypothesis '{}' was last executed {} days ago. "
                "Threat landscape and environment may have changed.".format(
                    hyp.get("title","?"), last_run),
                MITRE["stale"],
                "Re-execute with current data. Update criteria to reflect current environment. "
                "Add to quarterly hunt calendar.")

    def _detect_duplicates(self, hypotheses):
        tech_map = defaultdict(list)
        for hyp in hypotheses:
            tech = hyp.get("mitre_technique","")
            if tech:
                tech_map[tech].append(hyp)
        for tech, hyps in tech_map.items():
            if len(hyps) > 1:
                ids = [h["hypothesis_id"] for h in hyps]
                self._f(ids[0], "Overlapping Hypotheses for {}: {}".format(tech, ", ".join(ids)), "low",
                    "{} hypotheses cover the same MITRE technique {}.".format(len(hyps), tech),
                    MITRE["overlap"],
                    "Merge if redundant, or differentiate by scope (data source, time window).")

    def _coverage_gaps(self, hypotheses, ti_techniques):
        covered = {h.get("mitre_technique","").split(".")[0] for h in hypotheses}
        for tech in ti_techniques:
            if tech.split(".")[0] not in covered:
                self._f("GAP", "No Hunt Hypothesis for Active Technique: {}".format(tech), "high",
                    "Threat intelligence indicates '{}' is actively used against your sector "
                    "but no hunt hypothesis exists.".format(tech),
                    MITRE["gap"],
                    "Create a hypothesis for {}. Start with: what evidence would this technique "
                    "leave in YOUR environment? What log source contains that evidence?".format(tech))
