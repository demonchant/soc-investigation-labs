from collections import defaultdict
from datetime import datetime, timedelta, timezone


SENSITIVE_SCOPES = {
    "mail.readwrite",
    "mailboxsettings.readwrite",
    "directory.readwrite.all",
    "files.readwrite.all",
    "offline_access",
}


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class IdentityThreatDetector:
    def __init__(self):
        self.findings = []

    def add(self, title, severity, user, technique, evidence, recommendation):
        self.findings.append({
            "title": title,
            "severity": severity,
            "user": user,
            "mitre_technique": technique,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    def analyze(self, events):
        self.findings = []
        events = sorted(events, key=lambda event: parse_time(event["timestamp"]))
        by_user = defaultdict(list)
        by_token = defaultdict(list)
        for event in events:
            by_user[event.get("user", "unknown")].append(event)
            if event.get("token_id"):
                by_token[event["token_id"]].append(event)
            self.check_single_event(event)
        for user, user_events in by_user.items():
            self.check_mfa_sequence(user, user_events)
        for token, token_events in by_token.items():
            self.check_token_replay(token, token_events)
        return self.findings

    def check_single_event(self, event):
        user = event.get("user", "unknown")
        if event.get("event_type") == "oauth_consent":
            scopes = {scope.lower() for scope in event.get("scopes", [])}
            risky = sorted(scopes & SENSITIVE_SCOPES)
            if risky and not event.get("publisher_verified", False):
                self.add(
                    "Sensitive consent granted to an unverified application",
                    "critical",
                    user,
                    "T1098.003",
                    {"application": event.get("application"), "risky_scopes": risky},
                    "Revoke the grant, disable the application, and review mailbox activity.",
                )
        if event.get("event_type") == "authentication" and event.get("protocol") == "legacy":
            if event.get("result") == "success":
                self.add(
                    "Successful legacy authentication",
                    "high",
                    user,
                    "T1078",
                    {"source_ip": event.get("source_ip"), "country": event.get("country")},
                    "Disable legacy authentication and revoke active sessions.",
                )

    def check_mfa_sequence(self, user, events):
        mfa = [event for event in events if event.get("event_type") == "mfa_challenge"]
        for index, event in enumerate(mfa):
            start = parse_time(event["timestamp"])
            window = [
                candidate for candidate in mfa[index:]
                if parse_time(candidate["timestamp"]) <= start + timedelta(minutes=10)
            ]
            denied = [item for item in window if item.get("result") in {"denied", "timeout"}]
            if len(denied) >= 5:
                self.add(
                    "MFA push fatigue sequence",
                    "high",
                    user,
                    "T1621",
                    {"challenge_count": len(window), "denied_count": len(denied)},
                    "Reset credentials, revoke sessions, and require phishing resistant MFA.",
                )
                accepted = [item for item in window if item.get("result") == "approved"]
                if accepted:
                    self.add(
                        "MFA denial sequence followed by approval",
                        "critical",
                        user,
                        "T1078.004",
                        {"approved_at": accepted[0]["timestamp"], "prior_denials": len(denied)},
                        "Contain the account immediately and investigate the approving device.",
                    )
                break

    def check_token_replay(self, token, events):
        countries = {event.get("country") for event in events if event.get("country")}
        addresses = {event.get("source_ip") for event in events if event.get("source_ip")}
        if len(countries) > 1 and len(addresses) > 1:
            elapsed = parse_time(events[-1]["timestamp"]) - parse_time(events[0]["timestamp"])
            if elapsed <= timedelta(minutes=30):
                self.add(
                    "Possible session token replay",
                    "critical",
                    events[0].get("user", "unknown"),
                    "T1528",
                    {"token_id": token, "countries": sorted(countries), "source_ips": sorted(addresses)},
                    "Revoke the token, rotate credentials, and preserve identity provider logs.",
                )
