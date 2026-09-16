"""
Firewall Rule Auditor — Detects dangerous, misconfigured, stale, and
shadowed firewall rules. Produces a prioritised remediation report.
Covers: overly permissive rules, insecure protocols, stale rules,
internet-exposed management ports, shadow rules, and missing egress controls.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DANGEROUS_PORTS = {
    "23": "Telnet — cleartext protocol, credentials exposed",
    "21": "FTP — cleartext protocol, credentials exposed",
    "3389": "RDP — brute force and BlueKeep exposure if internet-facing",
    "22": "SSH — brute force exposure if open to 0.0.0.0/0",
    "445": "SMB — EternalBlue/WannaCry if internet-facing",
    "135": "RPC — remote code execution exposure",
    "5900": "VNC — cleartext remote desktop",
    "8080": "Alt-HTTP — often misconfigured, no TLS",
}

REVIEW_STALE_DAYS = 365
INTERNET_SOURCES = {"any", "0.0.0.0/0", "0.0.0.0", "::/0"}

MITRE = {
    "any_any":         "T1190 - Exploit Public-Facing Application (overly permissive rule)",
    "dangerous_port":  "T1021 / T1110 - Remote Services / Brute Force exposure",
    "insecure_proto":  "T1040 - Network Sniffing (cleartext protocol)",
    "no_comment":      "Configuration hygiene — undocumented rule",
    "stale":           "Configuration hygiene — unreviewed rule over 1 year old",
    "shadow":          "Configuration error — unreachable rule wastes policy space",
    "no_egress":       "T1048 - Exfiltration risk from unrestricted outbound",
}


class RuleAuditor:
    def __init__(self):
        self.findings = []

    def audit(self, rules):
        for rule in rules:
            if not rule.get("enabled"):
                continue
            self._check_any_any(rule)
            self._check_dangerous_ports(rule)
            self._check_insecure_protocols(rule)
            self._check_stale(rule)
            self._check_no_comment(rule)
            self._check_internet_management(rule)

        self._check_shadow_rules(rules)
        self._check_egress_control(rules)

        logger.info(f"Audit complete. {len(self.findings)} finding(s).")
        return self.findings

    def _finding(self, rule_id, title, severity, detail, mitre, recommendation):
        self.findings.append({
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "detail": detail,
            "mitre_technique": mitre,
            "recommendation": recommendation,
        })

    def _check_any_any(self, rule):
        src = str(rule.get("src", "")).lower()
        dst = str(rule.get("dst", "")).lower()
        port = str(rule.get("dst_port", "")).lower()
        if rule.get("action") == "allow" and src == "any" and dst == "any" and port == "any":
            self._finding(rule["id"], "Allow ANY → ANY Rule", "critical",
                f"Rule '{rule['name']}' permits all traffic from any source to any destination on any port.",
                MITRE["any_any"],
                "Replace with specific source/destination/port rules. Any ANY rule is a policy failure.")

    def _check_dangerous_ports(self, rule):
        port = str(rule.get("dst_port", ""))
        src = str(rule.get("src", "")).lower()
        if rule.get("action") == "allow" and port in DANGEROUS_PORTS:
            if src in INTERNET_SOURCES:
                sev = "critical"
                detail = f"Port {port} ({DANGEROUS_PORTS[port]}) exposed to the internet (src={rule.get('src')})."
            else:
                sev = "medium"
                detail = f"Port {port} ({DANGEROUS_PORTS[port]}) allowed internally. Review necessity."
            self._finding(rule["id"], f"Dangerous Port {port} Allowed", sev, detail,
                MITRE["dangerous_port"],
                f"Restrict port {port} to specific, named source IPs only. Consider replacing with secure alternative.")

    def _check_insecure_protocols(self, rule):
        port = str(rule.get("dst_port", ""))
        if rule.get("action") == "allow" and port in ("23", "21"):
            self._finding(rule["id"], f"Insecure Cleartext Protocol (Port {port})", "high",
                f"Rule '{rule['name']}' permits {DANGEROUS_PORTS.get(port, 'insecure protocol')}. All data including credentials transmitted in plaintext.",
                MITRE["insecure_proto"],
                "Replace Telnet with SSH. Replace FTP with SFTP or FTPS. Remove this rule.")

    def _check_stale(self, rule):
        reviewed = rule.get("last_reviewed")
        if not reviewed:
            self._finding(rule["id"], "Rule Never Reviewed", "medium",
                f"Rule '{rule['name']}' has no last-reviewed date on record.",
                MITRE["stale"],
                "Schedule immediate review. Assign rule owner. Add to quarterly firewall review cycle.")
            return
        try:
            last = datetime.fromisoformat(reviewed).replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - last).days
            if days > REVIEW_STALE_DAYS:
                self._finding(rule["id"], f"Stale Rule — Last Reviewed {days} Days Ago", "medium",
                    f"Rule '{rule['name']}' was last reviewed {days} days ago. Policy requires annual review.",
                    MITRE["stale"],
                    "Review and re-certify or remove. Add to quarterly firewall audit schedule.")
        except ValueError:
            pass

    def _check_no_comment(self, rule):
        if not rule.get("comment", "").strip():
            self._finding(rule["id"], "Undocumented Rule — No Comment", "low",
                f"Rule '{rule['name']}' has no business justification documented.",
                MITRE["no_comment"],
                "Add a comment explaining the business purpose, owner, and approval date for this rule.")

    def _check_internet_management(self, rule):
        src = str(rule.get("src", "")).lower()
        port = str(rule.get("dst_port", ""))
        mgmt_ports = {"22", "3389", "5900", "23", "443", "8443", "8080"}
        if rule.get("action") == "allow" and rule.get("direction") == "inbound":
            if src in INTERNET_SOURCES and port in mgmt_ports:
                self._finding(rule["id"], "Management Port Exposed to Internet", "critical",
                    f"Port {port} accessible from the internet (src={rule.get('src')}). Management interfaces must never be internet-facing.",
                    MITRE["dangerous_port"],
                    "Restrict to management VLAN or VPN egress IPs only. Apply MFA. Consider jump host architecture.")

    def _check_shadow_rules(self, rules):
        enabled = [r for r in rules if r.get("enabled")]
        for i, rule in enumerate(enabled):
            for earlier in enabled[:i]:
                if (earlier.get("action") == rule.get("action") and
                        earlier.get("direction") == rule.get("direction") and
                        earlier.get("src", "").lower() in ("any", rule.get("src", "").lower()) and
                        earlier.get("dst", "").lower() in ("any", rule.get("dst", "").lower()) and
                        str(earlier.get("dst_port", "")).lower() in ("any", str(rule.get("dst_port", "")).lower())):
                    self._finding(rule["id"], f"Shadow Rule — Superseded by {earlier['id']}", "medium",
                        f"Rule '{rule['name']}' will never be reached because '{earlier['name']}' ({earlier['id']}) matches all the same traffic first.",
                        MITRE["shadow"],
                        "Remove this rule or reorder the ruleset. Shadow rules indicate policy drift.")

    def _check_egress_control(self, rules):
        outbound_allows = [r for r in rules if r.get("enabled") and
                           r.get("action") == "allow" and r.get("direction") == "outbound"]
        any_any_out = [r for r in outbound_allows
                       if str(r.get("src","")).lower() == "any" and
                          str(r.get("dst","")).lower() == "any" and
                          str(r.get("dst_port","")).lower() == "any"]
        if any_any_out:
            self._finding(any_any_out[0]["id"], "No Outbound Egress Control", "high",
                "Allow ANY outbound rule exists. Unrestricted egress enables data exfiltration and C2 callbacks.",
                MITRE["no_egress"],
                "Implement egress filtering. Allow only required outbound ports/destinations. Block all else by default.")
