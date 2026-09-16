"""
Correlation Engine — Groups logs by source IP and checks whether
tag sequences defined in correlation rules occur within time windows.
Produces multi-stage attack chain detections across log sources.
"""
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

def _ts(s):
    try:
        return datetime.fromisoformat(str(s))
    except Exception:
        return None

class CorrelationEngine:
    def __init__(self, rules):
        self.rules = rules
        self.alerts = []

    def run(self, logs):
        # Group logs by src_ip
        by_ip = defaultdict(list)
        for log in logs:
            ip = log.get("src_ip")
            if ip:
                by_ip[ip].append(log)

        for ip, ip_logs in by_ip.items():
            ip_logs_sorted = sorted(ip_logs, key=lambda x: str(x.get("timestamp","")))
            for rule in self.rules:
                self._check_rule(rule, ip, ip_logs_sorted)

        logger.info(f"Correlation complete. {len(self.alerts)} alert(s).")
        return self.alerts

    def _check_rule(self, rule, ip, logs):
        sequence = rule["sequence"]
        window = rule["time_window_minutes"] * 60

        # Build tag timeline
        tag_events = defaultdict(list)
        for log in logs:
            for tag in log.get("_tags", []):
                tag_events[tag].append(log)

        # Special multi_host_logon check
        if "multi_host_logon" in sequence:
            hosts = {l.get("host") for l in logs if l.get("event") == "logon_success" and l.get("host")}
            if len(hosts) < 3:
                return

        # logon_fail_burst check
        if "logon_fail_burst" in sequence:
            fails = [l for l in logs if "logon_fail" in l.get("_tags",[])]
            if len(fails) < 5:
                return

        # Check all required sequence tags are present
        for tag in sequence:
            if tag in ("multi_host_logon", "logon_fail_burst"):
                continue
            if not tag_events.get(tag):
                return

        # Time window check: first and last event
        all_times = []
        for tag in sequence:
            if tag in ("multi_host_logon","logon_fail_burst"):
                continue
            for log in tag_events.get(tag,[]):
                t = _ts(log.get("timestamp"))
                if t:
                    all_times.append(t)

        if not all_times:
            return

        span = (max(all_times) - min(all_times)).total_seconds()
        if span > window:
            return

        # Build evidence
        evidence_logs = []
        for tag in sequence:
            for log in tag_events.get(tag, [])[:2]:
                entry = {"source": log.get("source"), "event": log.get("event"),
                         "timestamp": log.get("timestamp"), "tag": tag}
                if log.get("host"): entry["host"] = log["host"]
                if log.get("dst_ip"): entry["dst_ip"] = log["dst_ip"]
                if log.get("bytes"): entry["bytes"] = log["bytes"]
                if entry not in evidence_logs:
                    evidence_logs.append(entry)

        self.alerts.append({
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "src_ip": ip,
            "mitre_technique": rule["mitre"],
            "description": rule["description"],
            "sequence_matched": sequence,
            "span_seconds": round(span, 0),
            "evidence_count": len(evidence_logs),
            "evidence": evidence_logs[:6]
        })
