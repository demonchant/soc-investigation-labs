from collections import defaultdict
from datetime import datetime, timedelta, timezone


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class SaaSAccountTakeoverDetector:
    ACTIONS = {
        "external_forwarding_created": (35, "T1114.003", "critical"),
        "hidden_inbox_rule_created": (30, "T1114.003", "high"),
        "delegate_added": (25, "T1098", "high"),
        "recovery_method_changed": (25, "T1098", "high"),
        "mass_file_delete": (30, "T1485", "high"),
        "audit_logging_disabled": (40, "T1562.008", "critical"),
        "admin_role_assigned": (35, "T1098.003", "critical"),
    }

    def analyze(self, events):
        events = sorted(events, key=lambda event: parse_time(event["timestamp"]))
        findings = []
        by_user = defaultdict(list)
        for event in events:
            by_user[event.get("user", "unknown")].append(event)
            event_type = event.get("event_type")
            if event_type in self.ACTIONS:
                score, technique, severity = self.ACTIONS[event_type]
                findings.append({
                    "title": event_type.replace("_", " ").title(),
                    "severity": severity,
                    "user": event.get("user", "unknown"),
                    "risk_score": score,
                    "mitre_technique": technique,
                    "evidence": event,
                    "recommendation": self.recommendation(event_type),
                })

        for user, user_events in by_user.items():
            correlated = self.correlate_user(user, user_events)
            if correlated:
                findings.append(correlated)
        return sorted(findings, key=lambda item: (-item["risk_score"], item["user"]))

    def correlate_user(self, user, events):
        risky_signins = [
            event for event in events
            if event.get("event_type") == "sign_in" and event.get("risk") == "high"
        ]
        if not risky_signins:
            return None
        start = parse_time(risky_signins[0]["timestamp"])
        window = [
            event for event in events
            if start <= parse_time(event["timestamp"]) <= start + timedelta(hours=2)
        ]
        actions = [event for event in window if event.get("event_type") in self.ACTIONS]
        score = 25 + sum(self.ACTIONS[event["event_type"]][0] for event in actions)
        if score < 70:
            return None
        return {
            "title": "Correlated SaaS account takeover chain",
            "severity": "critical",
            "user": user,
            "risk_score": min(score, 100),
            "mitre_technique": "T1078.004",
            "evidence": {
                "risky_sign_in": risky_signins[0],
                "follow_on_actions": [event["event_type"] for event in actions],
            },
            "recommendation": "Disable the account, revoke sessions, reverse persistence, and preserve audit data.",
        }

    @staticmethod
    def recommendation(event_type):
        actions = {
            "external_forwarding_created": "Remove the forwarding target and inspect sent and deleted mail.",
            "hidden_inbox_rule_created": "Remove the rule and inspect mailbox rules through administrative tooling.",
            "delegate_added": "Remove the delegate and review all access performed by that principal.",
            "recovery_method_changed": "Restore trusted recovery methods and require credential reset.",
            "mass_file_delete": "Suspend destructive sessions and begin recovery from protected versions.",
            "audit_logging_disabled": "Restore audit logging and investigate the visibility gap.",
            "admin_role_assigned": "Remove unauthorized privilege and review every administrative action.",
        }
        return actions[event_type]
