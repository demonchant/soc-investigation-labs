"""
Detection Engine — Applies YAML-defined rules against normalized logs.
MITRE ATT&CK mapped. Supports: brute force, suspicious process, lateral movement.
"""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

MITRE_MAP = {
    "brute_force_attempt": "T1110 - Brute Force",
    "suspicious_process": "T1059 - Command and Scripting Interpreter",
    "lateral_movement": "T1021 - Remote Services"
}


class DetectionEngine:
    def __init__(self, rules):
        self.rules = rules
        self.handlers = {
            "brute_force_attempt": self._detect_bruteforce,
            "suspicious_process": self._detect_suspicious_process,
            "lateral_movement": self._detect_lateral_movement,
        }

    def process(self, logs):
        alerts = []
        for rule in self.rules:
            name = rule.get("name")
            handler = self.handlers.get(name)
            if handler:
                detected = handler(logs, rule)
                alerts.extend(detected)
                if detected:
                    logger.info(f"Rule '{name}' triggered {len(detected)} alert(s).")
            else:
                logger.warning(f"No handler registered for rule: '{name}'")
        return alerts

    def _detect_bruteforce(self, logs, rule):
        threshold = rule.get("threshold", 5)
        failed_logins = defaultdict(list)
        for log in logs:
            if log["event_type"] == "login_failed":
                failed_logins[log["source_ip"]].append(log["timestamp"])
        alerts = []
        for ip, timestamps in failed_logins.items():
            if len(timestamps) >= threshold:
                alerts.append({
                    "alert": "Brute Force Attempt Detected",
                    "source_ip": ip,
                    "attempts": len(timestamps),
                    "first_seen": timestamps[0],
                    "last_seen": timestamps[-1],
                    "mitre_technique": MITRE_MAP.get("brute_force_attempt"),
                    "severity": rule.get("severity", "high"),
                    "description": rule.get("description", "")
                })
        return alerts

    def _detect_suspicious_process(self, logs, rule):
        suspicious = rule.get("processes", [])
        alerts = []
        for log in logs:
            if log.get("process") in suspicious:
                alerts.append({
                    "alert": "Suspicious Process Execution",
                    "source_ip": log["source_ip"],
                    "user": log["user"],
                    "process": log["process"],
                    "timestamp": log["timestamp"],
                    "mitre_technique": MITRE_MAP.get("suspicious_process"),
                    "severity": rule.get("severity", "medium"),
                    "description": rule.get("description", "")
                })
        return alerts

    def _detect_lateral_movement(self, logs, rule):
        seen_hosts = defaultdict(set)
        for log in logs:
            if log["event_type"] == "login_success":
                seen_hosts[log["source_ip"]].add(log["host"])
        alerts = []
        for ip, hosts in seen_hosts.items():
            if len(hosts) >= rule.get("threshold", 3):
                alerts.append({
                    "alert": "Possible Lateral Movement",
                    "source_ip": ip,
                    "hosts_accessed": list(hosts),
                    "count": len(hosts),
                    "mitre_technique": MITRE_MAP.get("lateral_movement"),
                    "severity": rule.get("severity", "high"),
                    "description": rule.get("description", "")
                })
        return alerts
