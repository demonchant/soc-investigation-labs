"""
IAM Detection Engine — Evaluates normalised CloudTrail logs against threat rules.
"""
import logging
from detection.iam_rules import RULES
from alerts.alert_manager import create_alert

logger = logging.getLogger(__name__)


class IAMDetectionEngine:
    def run(self, logs):
        alert_count = 0
        for log in logs:
            alert_count += self._evaluate(log)
        logger.info(f"Detection complete. {alert_count} alert(s) generated.")
        return alert_count

    def _evaluate(self, log):
        count = 0
        count += self._check(log, "root_login",
            lambda l: l["event_name"] == RULES["root_login"]["event_name"] and l["user"] == "root")
        count += self._check(log, "no_mfa_root",
            lambda l: l["event_name"] == "ConsoleLogin" and l["user"] == "root" and not l.get("mfa_used", True))
        count += self._check(log, "new_access_key",
            lambda l: l["event_name"] == RULES["new_access_key"]["event_name"])
        count += self._check(log, "privilege_escalation",
            lambda l: l["event_name"] == RULES["privilege_escalation"]["event_name"])
        count += self._check(log, "unusual_region",
            lambda l: l["region"] in RULES["unusual_region"]["suspicious_regions"])
        count += self._check(log, "iam_user_creation",
            lambda l: l["event_name"] == "CreateUser")
        count += self._check(log, "console_login_failure",
            lambda l: l["event_name"] == "ConsoleLogin" and l.get("status") == "failure")
        count += self._check(log, "security_group_modified",
            lambda l: l["event_name"] == "AuthorizeSecurityGroupIngress")
        return count

    def _check(self, log, rule_name, condition):
        try:
            if condition(log):
                rule = RULES[rule_name]
                create_alert(
                    title=self._title_for(rule_name),
                    severity=rule["severity"],
                    mitre=rule.get("mitre", ""),
                    description=rule.get("description", ""),
                    log=log
                )
                return 1
        except Exception as e:
            logger.error(f"Error evaluating rule {rule_name}: {e}")
        return 0

    def _title_for(self, rule_name):
        titles = {
            "root_login": "Root Account Login Detected",
            "no_mfa_root": "Root Login Without MFA",
            "new_access_key": "New IAM Access Key Created",
            "privilege_escalation": "IAM Privilege Escalation Attempt",
            "unusual_region": "API Activity from High-Risk Region",
            "iam_user_creation": "New IAM User Created",
            "console_login_failure": "Console Login Failure",
            "security_group_modified": "Security Group Modified"
        }
        return titles.get(rule_name, rule_name.replace("_", " ").title())
