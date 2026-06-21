import re, logging
logger = logging.getLogger(__name__)

MITRE = {
    "wildcard":   "T1078.004 - Valid Accounts: Cloud Accounts (overprivileged)",
    "mfa":        "T1556.006 - Modify Authentication Process: MFA bypass risk",
    "unused":     "T1078.004 - Valid Accounts: Stale credential abuse",
    "privesc":    "T1078.004 - Valid Accounts: IAM privilege escalation path",
    "passrole":   "T1098.003 - Account Manipulation: PassRole abuse",
    "inline":     "T1098 - Account Manipulation: Inline policy persistence",
    "keyleak":    "T1552.005 - Unsecured Credentials: Cloud Instance Metadata",
    "pubaccess":  "T1530 - Data from Cloud Storage Object (public S3/bucket)",
}

PRIVESC_ACTIONS = {
    "iam:CreateAccessKey":       "Create access key for any user → credential theft",
    "iam:CreateLoginProfile":    "Create console password for any user",
    "iam:UpdateLoginProfile":    "Change another user's console password",
    "iam:AttachUserPolicy":      "Attach AdministratorAccess to any user",
    "iam:AttachRolePolicy":      "Attach AdministratorAccess to any role",
    "iam:PutUserPolicy":         "Inline admin policy on any user",
    "iam:AddUserToGroup":        "Add self to admin group",
    "iam:PassRole":              "Pass privileged role to attacker-controlled resource",
    "sts:AssumeRole":            "Assume any role including admin roles",
    "iam:CreatePolicyVersion":   "Overwrite existing policy with admin version",
    "lambda:CreateFunction":     "Deploy Lambda with privileged role → code execution",
    "ec2:RunInstances":          "Launch EC2 with admin role → metadata credential theft",
}

class IAMAuditor:
    def __init__(self): self.findings = []

    def audit_all(self, data):
        for user in data.get("users", []): self._audit_user(user)
        for role in data.get("roles", []): self._audit_role(role)
        for policy in data.get("policies", []): self._audit_policy(policy)
        return self.findings

    def _f(self, entity, etype, title, sev, detail, mitre, rec):
        self.findings.append({"entity": entity, "entity_type": etype, "title": title,
            "severity": sev, "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    def _audit_user(self, u):
        name = u["username"]

        if not u.get("mfa_enabled"):
            self._f(name, "user", "MFA Not Enabled", "critical",
                "User '{}' has no MFA — password alone = account takeover risk.".format(name),
                MITRE["mfa"], "Enforce MFA via IAM policy: aws:MultiFactorAuthPresent = true.")

        days = u.get("password_last_used_days", 0)
        if days > 90:
            self._f(name, "user", "Inactive User — Password Unused {} Days".format(days), "high",
                "Dormant accounts are prime targets for credential stuffing.",
                MITRE["unused"], "Disable or delete users inactive > 90 days. Review quarterly.")

        for key in u.get("access_keys", []):
            age = key.get("age_days", 0)
            if age > 90:
                self._f(name, "user", "Access Key Older Than {} Days".format(age), "high",
                    "Key '{}' created {} days ago — long-lived keys increase breach window.".format(
                        key.get("key_id", "?"), age),
                    MITRE["keyleak"], "Rotate access keys every 90 days. Use IAM roles where possible.")
            if not key.get("used_last_30_days") and age > 30:
                self._f(name, "user", "Unused Access Key: {}".format(key.get("key_id","?")), "medium",
                    "Key has not been used in 30+ days — stale credentials.",
                    MITRE["unused"], "Deactivate then delete unused access keys.")

        for policy in u.get("attached_policies", []):
            if policy in ("AdministratorAccess", "PowerUserAccess"):
                self._f(name, "user", "Admin Policy Directly Attached: {}".format(policy), "critical",
                    "Direct admin attachment bypasses role-based access control.",
                    MITRE["wildcard"], "Remove direct admin policy. Use IAM roles with SCPs instead.")

        if u.get("inline_policies"):
            self._f(name, "user", "Inline Policies Attached ({})".format(len(u["inline_policies"])),
                "medium", "Inline policies are harder to audit and can hide privilege grants.",
                MITRE["inline"], "Convert inline policies to managed policies for visibility.")

        for group in u.get("groups", []):
            if "admin" in group.lower():
                self._f(name, "user", "Member of Admin Group: {}".format(group), "high",
                    "Group membership grants admin privileges — verify this is intentional.",
                    MITRE["wildcard"], "Audit admin group membership. Apply least privilege.")

    def _audit_role(self, r):
        name = r["role_name"]

        trust = r.get("trust_policy", {})
        principals = trust.get("principals", [])
        if "*" in principals:
            self._f(name, "role", "Role Trust Policy Allows Any Principal (*)", "critical",
                "Any AWS account or entity can assume role '{}'.".format(name),
                MITRE["privesc"], "Restrict trust policy to specific account IDs and services.")

        if r.get("max_session_duration_hours", 1) > 12:
            self._f(name, "role", "Role Session Duration Exceeds 12 Hours", "medium",
                "Long sessions increase exposure window if token is stolen.",
                MITRE["privesc"], "Reduce MaxSessionDuration to 1 hour for sensitive roles.")

        for policy in r.get("attached_policies", []):
            if policy == "AdministratorAccess":
                self._f(name, "role", "AdministratorAccess Attached to Role", "critical",
                    "Role '{}' has full admin — any service using it = full AWS access.".format(name),
                    MITRE["wildcard"], "Replace with scoped permission set. Apply least privilege.")

        if r.get("cross_account_access") and not r.get("external_id_required"):
            self._f(name, "role", "Cross-Account Role Without ExternalId Condition", "high",
                "Susceptible to confused deputy attack — any account can assume this role.",
                MITRE["privesc"], "Add sts:ExternalId condition to trust policy.")

    def _audit_policy(self, p):
        name = p["policy_name"]
        stmts = p.get("statements", [])

        for stmt in stmts:
            effect = stmt.get("effect", "").upper()
            actions = stmt.get("actions", [])
            resources = stmt.get("resources", [])
            if effect != "ALLOW":
                continue

            # Wildcard action
            if "*" in actions or "iam:*" in actions:
                self._f(name, "policy", "Wildcard Action in Policy: {}".format(
                    [a for a in actions if "*" in a][:3]), "critical",
                    "Policy '{}' grants unrestricted actions — equivalent to admin.".format(name),
                    MITRE["wildcard"], "Replace '*' with explicit action list. Review quarterly.")

            # Wildcard resource
            if "*" in resources and any("*" not in a for a in actions):
                self._f(name, "policy", "Actions Apply to All Resources (*)", "high",
                    "Actions {} apply to every resource in the account.".format(actions[:3]),
                    MITRE["wildcard"], "Scope resources to specific ARNs.")

            # Privilege escalation actions
            for action in actions:
                if action in PRIVESC_ACTIONS:
                    self._f(name, "policy",
                        "Privilege Escalation Action Granted: {}".format(action), "critical",
                        PRIVESC_ACTIONS[action],
                        MITRE["privesc"],
                        "Remove {} unless absolutely required. Add condition constraints.".format(action))

            # PassRole specifically
            if "iam:PassRole" in actions and "*" in resources:
                self._f(name, "policy", "iam:PassRole Granted on All Resources", "critical",
                    "Attacker can pass any role to any service they control.",
                    MITRE["passrole"], "Restrict PassRole to specific role ARNs only.")

            # S3 public access via policy
            if any("s3:" in a for a in actions) and "*" in resources:
                self._f(name, "policy", "S3 Actions on All Resources (*)", "high",
                    "Grants access to every S3 bucket in account.",
                    MITRE["pubaccess"], "Scope to specific bucket ARNs.")
