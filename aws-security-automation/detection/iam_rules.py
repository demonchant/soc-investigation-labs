"""
IAM Detection Rules — Defines threat signatures for AWS IAM monitoring.
Maps to MITRE ATT&CK Cloud techniques.
"""

RULES = {
    "root_login": {
        "event_name": "ConsoleLogin",
        "user_type": "root",
        "severity": "critical",
        "mitre": "T1078.004 - Cloud Accounts",
        "description": "AWS root account console login detected — should never occur in production."
    },
    "new_access_key": {
        "event_name": "CreateAccessKey",
        "severity": "high",
        "mitre": "T1098.001 - Additional Cloud Credentials",
        "description": "New IAM access key created — verify if authorised."
    },
    "privilege_escalation": {
        "event_name": "AttachUserPolicy",
        "severity": "high",
        "mitre": "T1098 - Account Manipulation",
        "description": "IAM policy attached to user — possible privilege escalation."
    },
    "unusual_region": {
        "suspicious_regions": ["RU", "CN", "KP", "IR", "SY"],
        "severity": "medium",
        "mitre": "T1535 - Unused/Unsupported Cloud Regions",
        "description": "API activity from high-risk geographic region."
    },
    "no_mfa_root": {
        "event_name": "ConsoleLogin",
        "user_type": "root",
        "mfa_used": False,
        "severity": "critical",
        "mitre": "T1078.004 - Cloud Accounts",
        "description": "Root login without MFA — critical misconfiguration."
    },
    "iam_user_creation": {
        "event_name": "CreateUser",
        "severity": "medium",
        "mitre": "T1136.003 - Cloud Account",
        "description": "New IAM user created — verify if authorised."
    },
    "console_login_failure": {
        "event_name": "ConsoleLogin",
        "status": "failure",
        "severity": "low",
        "mitre": "T1110 - Brute Force",
        "description": "Failed console login attempt detected."
    },
    "security_group_modified": {
        "event_name": "AuthorizeSecurityGroupIngress",
        "severity": "high",
        "mitre": "T1562.007 - Disable or Modify Cloud Firewall",
        "description": "Security group ingress rule modified — potential firewall weakening."
    }
}
