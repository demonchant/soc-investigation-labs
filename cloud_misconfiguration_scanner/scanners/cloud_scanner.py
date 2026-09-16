"""
Cloud Misconfiguration Scanner
Checks AWS infrastructure configuration against security best practices.
Covers: S3 bucket exposure, security group rules, IAM hygiene,
CloudTrail coverage, and password policy strength.
Maps findings to MITRE ATT&CK and CIS AWS Benchmark controls.
"""
import logging
logger = logging.getLogger(__name__)

INTERNET_SOURCES = {"0.0.0.0/0", "::/0", "any"}
SENSITIVE_PORTS = {"22":"SSH","3389":"RDP","5900":"VNC","3306":"MySQL",
                   "5432":"PostgreSQL","27017":"MongoDB","6379":"Redis","1521":"Oracle"}

MITRE = {
    "s3_public_write":   "T1190 - Exploit Public-Facing Application (Public S3 Write)",
    "s3_public_read":    "T1530 - Data from Cloud Storage Object",
    "s3_no_encrypt":     "T1537 - Transfer Data to Cloud Account",
    "db_port_exposed":   "T1190 - Exploit Public-Facing Application (DB Exposure)",
    "mgmt_port_exposed": "T1021 - Remote Services (RDP/SSH/VNC from internet)",
    "no_mfa":            "T1078 - Valid Accounts (No MFA)",
    "stale_key":         "T1098.001 - Account Manipulation: Additional Cloud Credentials",
    "overprivileged":    "T1098 - Account Manipulation (Excessive Permissions)",
    "cloudtrail_gap":    "T1562.008 - Impair Defenses: Disable Cloud Logs",
    "weak_password":     "T1110 - Brute Force (Weak Password Policy)",
}

CIS = {
    "s3_public_write":   "CIS AWS 2.1.2",
    "no_mfa":            "CIS AWS 1.10",
    "cloudtrail_gap":    "CIS AWS 3.1 / 3.2",
    "weak_password":     "CIS AWS 1.8 / 1.9",
    "db_port_exposed":   "CIS AWS 5.2",
}


class CloudScanner:
    def __init__(self):
        self.findings = []

    def scan(self, config):
        self._scan_s3(config.get("s3_buckets", []))
        self._scan_security_groups(config.get("security_groups", []))
        self._scan_iam(config.get("iam_users", []))
        self._scan_cloudtrail(config.get("cloudtrail", {}))
        self._scan_password_policy(config.get("password_policy", {}))
        logger.info(f"Cloud scan complete. {len(self.findings)} finding(s).")
        return self.findings

    def _finding(self, resource, title, severity, detail, mitre, recommendation, cis=None):
        f = {"resource": resource, "title": title, "severity": severity,
             "detail": detail, "mitre_technique": mitre, "recommendation": recommendation}
        if cis:
            f["cis_control"] = cis
        self.findings.append(f)

    def _scan_s3(self, buckets):
        for b in buckets:
            name = b["name"]
            if b.get("public_write"):
                self._finding(f"S3:{name}", "S3 Bucket Publicly Writable", "critical",
                    f"Bucket '{name}' allows public write — anyone can upload files.",
                    MITRE["s3_public_write"], "Remove public write ACL immediately. Enable Block Public Access.",
                    CIS["s3_public_write"])
            if b.get("public_read") and "hr" in name.lower() or "backup" in name.lower() or "record" in name.lower():
                self._finding(f"S3:{name}", "Sensitive S3 Bucket Publicly Readable", "critical",
                    f"Bucket '{name}' appears to contain sensitive data and is publicly readable.",
                    MITRE["s3_public_read"], "Enable Block Public Access. Use pre-signed URLs for authorised access.")
            if not b.get("encryption"):
                self._finding(f"S3:{name}", "S3 Bucket Not Encrypted", "high",
                    f"Bucket '{name}' has no server-side encryption — data at rest is unprotected.",
                    MITRE["s3_no_encrypt"], "Enable SSE-S3 or SSE-KMS encryption on the bucket.")
            if not b.get("versioning"):
                self._finding(f"S3:{name}", "S3 Bucket Versioning Disabled", "medium",
                    f"Bucket '{name}' has no versioning — data deletion or ransomware cannot be recovered.",
                    MITRE["s3_no_encrypt"], "Enable versioning. Consider MFA delete for critical buckets.")
            if not b.get("logging"):
                self._finding(f"S3:{name}", "S3 Access Logging Disabled", "medium",
                    f"Bucket '{name}' has no access logging — cannot audit who accessed what.",
                    MITRE["cloudtrail_gap"], "Enable S3 server access logging to a separate audit bucket.")

    def _scan_security_groups(self, sgs):
        for sg in sgs:
            for rule in sg.get("rules", []):
                src = rule.get("src", "")
                port = str(rule.get("port", ""))
                if src in INTERNET_SOURCES:
                    if port in SENSITIVE_PORTS:
                        is_db = port in {"3306","5432","27017","6379","1521"}
                        sev = "critical"
                        mitre_key = "db_port_exposed" if is_db else "mgmt_port_exposed"
                        self._finding(
                            f"SG:{sg['id']}:{sg['name']}",
                            f"{'Database' if is_db else 'Management'} Port {port} ({SENSITIVE_PORTS[port]}) Exposed to Internet",
                            sev,
                            f"Security group '{sg['name']}' allows inbound {SENSITIVE_PORTS[port]} from 0.0.0.0/0.",
                            MITRE[mitre_key],
                            f"Restrict port {port} to specific management IPs or VPN egress only.",
                            CIS.get("db_port_exposed"))

    def _scan_iam(self, users):
        for u in users:
            name = u["username"]
            if not u.get("mfa_enabled") and u.get("console_access"):
                self._finding(f"IAM:{name}", "IAM User Console Access Without MFA", "critical",
                    f"User '{name}' can log into the AWS Console without MFA.",
                    MITRE["no_mfa"], "Enforce MFA for all IAM users with console access.", CIS["no_mfa"])
            if u.get("access_keys", 0) > 1:
                self._finding(f"IAM:{name}", "Multiple Active Access Keys", "high",
                    f"User '{name}' has {u['access_keys']} active access keys — only one should be active.",
                    MITRE["stale_key"], "Deactivate old access keys. Rotate regularly.")
            if u.get("last_used_days", 0) > 90:
                self._finding(f"IAM:{name}", f"Stale Access Key (Unused {u['last_used_days']} Days)", "high",
                    f"User '{name}' has not used their access key in {u['last_used_days']} days.",
                    MITRE["stale_key"], "Deactivate or delete unused access keys immediately.")
            for policy in u.get("policies", []):
                if policy in ("AdministratorAccess", "PowerUserAccess"):
                    self._finding(f"IAM:{name}", f"Overprivileged IAM User ({policy})", "high",
                        f"User '{name}' has '{policy}' — violates principle of least privilege.",
                        MITRE["overprivileged"], "Replace with minimum required permissions. Use SCPs for guardrails.")

    def _scan_cloudtrail(self, ct):
        if not ct.get("enabled"):
            self._finding("CloudTrail", "CloudTrail Logging Disabled", "critical",
                "CloudTrail is disabled — all AWS API activity is unaudited.",
                MITRE["cloudtrail_gap"], "Enable CloudTrail immediately across all regions.", CIS["cloudtrail_gap"])
            return
        if not ct.get("multi_region"):
            self._finding("CloudTrail", "CloudTrail Not Multi-Region", "high",
                "CloudTrail only covers one region — activity in other regions is unlogged.",
                MITRE["cloudtrail_gap"], "Enable multi-region CloudTrail trail.", CIS["cloudtrail_gap"])
        if not ct.get("log_validation"):
            self._finding("CloudTrail", "CloudTrail Log File Validation Disabled", "medium",
                "Log file integrity validation is off — logs could be tampered with undetected.",
                MITRE["cloudtrail_gap"], "Enable log file validation to detect tampering.")

    def _scan_password_policy(self, pp):
        issues = []
        if pp.get("min_length", 0) < 14:
            issues.append(f"minimum length {pp.get('min_length',0)} (should be ≥14)")
        if not pp.get("require_uppercase"):
            issues.append("uppercase not required")
        if not pp.get("require_numbers"):
            issues.append("numbers not required")
        if not pp.get("require_symbols"):
            issues.append("symbols not required")
        if pp.get("max_age_days", 0) == 0:
            issues.append("no password expiry policy")
        if pp.get("reuse_prevention", 0) < 24:
            issues.append(f"password reuse only prevented for {pp.get('reuse_prevention',0)} generations (should be 24)")
        if issues:
            self._finding("PasswordPolicy", "Weak IAM Password Policy", "high",
                "Issues: " + "; ".join(issues),
                MITRE["weak_password"], "Enforce: min 14 chars, uppercase, numbers, symbols, 90-day expiry, 24 history.",
                CIS["weak_password"])
