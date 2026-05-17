import yaml, logging, json
from collections import defaultdict
from database.db import get_connection
from alerts.alert_manager import create_alert

logger = logging.getLogger(__name__)


class RuleEngine:
    def __init__(self, rules_path="detection/rules.yaml"):
        with open(rules_path, "r") as f:
            self.rules = yaml.safe_load(f)

    def run(self):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs")
        rows = cursor.fetchall()
        conn.close()

        logs = [dict(row) for row in rows]
        logger.info(f"Running detection on {len(logs)} log entries.")

        self.detect_bruteforce(logs)
        self.detect_credential_stuffing(logs)
        self.detect_process_anomaly(logs)
        self.detect_multi_host_auth(logs)

    def detect_bruteforce(self, logs):
        rule = self.rules.get("brute_force", {})
        counter = defaultdict(list)
        for log in logs:
            if log["event_type"] == "login_failed":
                counter[log["source_ip"]].append(log["timestamp"])
        for ip, timestamps in counter.items():
            if len(timestamps) >= rule.get("threshold", 5):
                create_alert(
                    rule_name="brute_force",
                    severity=rule.get("severity", "high"),
                    source_ip=ip,
                    description=f"Brute force from {ip}: {len(timestamps)} failed attempts.",
                    mitre=rule.get("mitre", "T1110"),
                    evidence=json.dumps({"attempts": len(timestamps), "first": timestamps[0], "last": timestamps[-1]})
                )

    def detect_credential_stuffing(self, logs):
        rule = self.rules.get("suspicious_login_success", {})
        failures = defaultdict(int)
        successes = []
        for log in logs:
            if log["event_type"] == "login_failed":
                failures[log["source_ip"]] += 1
            if log["event_type"] == "login_success":
                successes.append(log["source_ip"])
        for ip in successes:
            if failures.get(ip, 0) >= rule.get("threshold", 3):
                create_alert(
                    rule_name="suspicious_login_success",
                    severity=rule.get("severity", "medium"),
                    source_ip=ip,
                    description=f"Login success after {failures[ip]} failures from {ip}.",
                    mitre=rule.get("mitre", "T1110.003"),
                    evidence=json.dumps({"prior_failures": failures[ip]})
                )

    def detect_process_anomaly(self, logs):
        rule = self.rules.get("process_anomaly", {})
        suspicious = rule.get("suspicious_processes", [])
        for log in logs:
            if log["event_type"] == "process_exec" and log.get("process") in suspicious:
                create_alert(
                    rule_name="process_anomaly",
                    severity=rule.get("severity", "high"),
                    source_ip=log["source_ip"],
                    description=f"Suspicious process [{log['process']}] on {log.get('host','unknown')} by {log.get('user','unknown')}.",
                    mitre=rule.get("mitre", "T1059"),
                    evidence=json.dumps({"process": log["process"], "user": log.get("user"), "host": log.get("host")})
                )

    def detect_multi_host_auth(self, logs):
        rule = self.rules.get("multi_host_auth", {})
        user_hosts = defaultdict(set)
        for log in logs:
            if log["event_type"] == "login_success" and log.get("user") != "unknown":
                user_hosts[log["user"]].add(log.get("host", "unknown"))
        for user, hosts in user_hosts.items():
            if len(hosts) >= rule.get("threshold", 3):
                create_alert(
                    rule_name="multi_host_auth",
                    severity=rule.get("severity", "high"),
                    source_ip="N/A",
                    description=f"User [{user}] authenticated to {len(hosts)} hosts.",
                    mitre=rule.get("mitre", "T1021"),
                    evidence=json.dumps({"user": user, "hosts": list(hosts)})
                )
