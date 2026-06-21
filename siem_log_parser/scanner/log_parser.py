import re, logging
from datetime import datetime, timezone
logger = logging.getLogger(__name__)

MITRE = {
    "failed_auth":  "T1110 - Brute Force: Failed authentication",
    "privesc":      "T1548 - Abuse Elevation Control Mechanism",
    "recon":        "T1046 - Network Service Discovery",
    "webattack":    "T1190 - Exploit Public-Facing Application",
    "malware":      "T1059 - Command and Scripting Interpreter",
    "exfil":        "T1048 - Exfiltration Over Alternative Protocol",
    "persistence":  "T1053 - Scheduled Task/Job",
    "lateral":      "T1021 - Remote Services",
}

# Windows Event ID → normalized action mapping
WIN_EVENT_MAP = {
    4624: ("auth_success",   "low",    "lateral"),
    4625: ("auth_failure",   "medium", "failed_auth"),
    4648: ("explicit_creds", "high",   "lateral"),
    4672: ("special_priv",   "high",   "privesc"),
    4688: ("process_create", "medium", "malware"),
    4698: ("task_created",   "high",   "persistence"),
    4719: ("audit_change",   "critical","privesc"),
    4732: ("group_add",      "high",   "privesc"),
    1102: ("log_cleared",    "critical","malware"),
    7045: ("service_install","high",   "persistence"),
}

SYSLOG_PATTERNS = [
    (re.compile(r"(failed|failure|invalid|refused)\s+(password|login|auth)", re.I),
     "auth_failure", "medium", "failed_auth"),
    (re.compile(r"(accepted|session opened for user)", re.I),
     "auth_success", "low", "lateral"),
    (re.compile(r"(sudo|su):.*COMMAND", re.I),
     "sudo_exec", "high", "privesc"),
    (re.compile(r"(segfault|buffer overflow|stack smashing)", re.I),
     "exploit_attempt", "critical", "webattack"),
    (re.compile(r"(crontab|cron\[)", re.I),
     "cron_activity", "medium", "persistence"),
    (re.compile(r"(iptables|firewall|ufw)\s+(drop|reject|block)", re.I),
     "firewall_block", "low", "recon"),
]

APACHE_PATTERNS = [
    (re.compile(r'" 200 '),  "web_success", "low",    "recon"),
    (re.compile(r'" 40[134] '), "web_client_err", "low", "recon"),
    (re.compile(r'" 500 '),  "web_server_err", "medium", "webattack"),
    (re.compile(r'(union.*select|or 1=1|--|xp_cmdshell)', re.I),
     "sqli_attempt", "critical", "webattack"),
    (re.compile(r'(<script|alert\(|onerror=)', re.I),
     "xss_attempt", "high", "webattack"),
    (re.compile(r'(\.\./|%2e%2e|directory traversal)', re.I),
     "path_traversal", "high", "webattack"),
    (re.compile(r'(nikto|sqlmap|nmap|masscan|zgrab|nuclei)', re.I),
     "scanner_ua", "medium", "recon"),
    (re.compile(r'" (40[134]|500) .{1,10}$'),
     "error_response", "low", "recon"),
]

ANOMALY_CHECKS = [
    (lambda e: e.get("action")=="auth_failure" and int(e.get("count",1))>10,
     "Burst authentication failures", "high", "failed_auth"),
    (lambda e: e.get("src_port",0) < 1024 and e.get("action")=="auth_success",
     "Auth success from privileged source port", "medium", "lateral"),
    (lambda e: e.get("hour",12) < 6 or e.get("hour",12) >= 22,
     "Activity outside business hours", "medium", "lateral"),
]

class LogParser:
    def __init__(self): self.findings = []

    def parse_all(self, data):
        for entry in data.get("log_entries", []):
            src = entry.get("log_source", "unknown").lower()
            if "windows" in src:   self._parse_windows(entry)
            elif "syslog" in src:  self._parse_syslog(entry)
            elif "apache" in src or "nginx" in src: self._parse_web(entry)
        return self.findings

    def _f(self, raw, normalized, action, sev, detail, mitre, rec):
        self.findings.append({
            "raw_log":    raw[:120], "normalized_action": action,
            "severity":   sev,       "detail": detail,
            "mitre_technique": mitre, "recommendation": rec,
            "source":     normalized.get("source","?"),
            "timestamp":  normalized.get("timestamp","?"),
            "src_ip":     normalized.get("src_ip",""),
            "username":   normalized.get("username",""),
        })

    def _parse_windows(self, entry):
        eid  = entry.get("event_id",0)
        norm = self._norm(entry)
        if eid not in WIN_EVENT_MAP:
            return
        action, sev, mitre_key = WIN_EVENT_MAP[eid]
        detail = "{}: {} on {} (user: {})".format(
            action, entry.get("message",""), norm["source"], norm["username"])
        if sev in ("critical","high"):
            self._f(entry.get("raw",""), norm, action, sev, detail,
                MITRE[mitre_key], self._rec(action, norm))
        self._check_anomalies({**norm, "action": action})

    def _parse_syslog(self, entry):
        raw  = entry.get("raw","")
        norm = self._norm(entry)
        for pattern, action, sev, mitre_key in SYSLOG_PATTERNS:
            if pattern.search(raw):
                self._f(raw, norm, action, sev,
                    "Syslog: {} on {} (src: {})".format(
                        action, norm["source"], norm.get("src_ip","")),
                    MITRE[mitre_key], self._rec(action, norm))
                break
        self._check_anomalies({**norm, "action": "syslog"})

    def _parse_web(self, entry):
        raw  = entry.get("raw","")
        norm = self._norm(entry)
        for pattern, action, sev, mitre_key in APACHE_PATTERNS:
            if pattern.search(raw):
                if sev in ("critical","high","medium"):
                    self._f(raw, norm, action, sev,
                        "Web: {} from {} — {}".format(
                            action, norm.get("src_ip","?"), raw[50:100]),
                        MITRE[mitre_key], self._rec(action, norm))
                break

    def _check_anomalies(self, norm):
        for check, desc, sev, mitre_key in ANOMALY_CHECKS:
            try:
                if check(norm):
                    self._f("", norm, "anomaly", sev,
                        "Anomaly: {} — user: {}, src: {}".format(
                            desc, norm.get("username",""), norm.get("src_ip","")),
                        MITRE[mitre_key], "Investigate user activity and src IP context.")
            except Exception:
                pass

    def _norm(self, entry):
        ts = entry.get("timestamp","")
        hour = 12
        try:
            hour = datetime.fromisoformat(ts.replace("Z","+00:00")).hour
        except Exception:
            pass
        return {
            "source":    entry.get("host", entry.get("log_source","?")),
            "timestamp": ts,
            "src_ip":    entry.get("src_ip",""),
            "username":  entry.get("username", entry.get("user","")),
            "count":     entry.get("count",1),
            "src_port":  entry.get("src_port",0),
            "hour":      hour,
        }

    def _rec(self, action, norm):
        recs = {
            "auth_failure":   "Investigate source IP {}. Enable account lockout.".format(norm.get("src_ip","")),
            "log_cleared":    "CRITICAL: Preserve logs off-host. Initiate IR investigation.",
            "task_created":   "Audit scheduled task payload. Verify with system owner.",
            "audit_change":   "Revert audit policy. Investigate account making change.",
            "sqli_attempt":   "Block src IP at WAF. Audit database for successful injection.",
            "xss_attempt":    "Block src IP. Verify output encoding in application code.",
            "path_traversal": "Block src IP. Verify file access controls on web root.",
            "sudo_exec":      "Review sudoers file. Verify command was authorized.",
            "exploit_attempt":"Isolate host. Memory forensics for shellcode.",
            "special_priv":   "Verify privilege use was authorized. Check for token theft.",
        }
        return recs.get(action, "Review full log context. Correlate with related events.")
