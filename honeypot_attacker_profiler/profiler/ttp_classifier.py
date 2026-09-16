"""
TTP Classifier — Maps honeypot payloads and actions to MITRE ATT&CK techniques.
Analyses SSH commands, HTTP requests, FTP transfers, RDP attempts.
"""
import re
import logging
logger = logging.getLogger(__name__)

COMMAND_SIGS = [
    (r"wget|curl|fetch",           "T1105",     "Ingress Tool Transfer"),
    (r"chmod|chown",               "T1222",     "File/Directory Permissions Mod"),
    (r"crontab|/etc/crontab",      "T1053.003", "Scheduled Task — Cron"),
    (r"cat /etc/passwd|/etc/shadow","T1003.008","Credential Dumping — /etc/passwd"),
    (r"/tmp/\.",                   "T1564.001", "Hidden Files and Directories"),
    (r"useradd|adduser",           "T1136.001", "Local Account Creation"),
    (r"nc |netcat",                "T1095",     "Non-Application Layer Protocol"),
    (r"base64|xxd",                "T1027",     "Obfuscated Files or Information"),
    (r"ps aux|top|who",            "T1057",     "Process Discovery"),
    (r"uname|/etc/os-release",     "T1082",     "System Information Discovery"),
    (r"ifconfig|ip addr",          "T1016",     "System Network Config Discovery"),
]

HTTP_SIGS = [
    (r"\.env|config\.php|wp-admin","T1083",     "File and Directory Discovery"),
    (r"OR.+1.+1|UNION SELECT",     "T1190",     "Exploit Public-Facing App (SQLi)"),
    (r"<script>|javascript:",      "T1059.007", "JavaScript Injection (XSS)"),
    (r"shell\.php|cmd\.php",       "T1505.003", "Web Shell"),
]

ACTION_MITRE = {
    "auth_attempt":   ("T1110",     "Brute Force"),
    "auth_success":   ("T1078",     "Valid Accounts — Compromised Credential"),
    "command_exec":   ("T1059",     "Command and Scripting Interpreter"),
    "file_upload":    ("T1505.003", "Web Shell / Malicious File Upload"),
    "http_probe":     ("T1595.002", "Vulnerability Scanning"),
    "sqli_attempt":   ("T1190",     "Exploit Public-Facing Application"),
    "xss_attempt":    ("T1059.007", "XSS / Script Injection"),
}


class TTPClassifier:
    def classify(self, sessions):
        profiles = {}
        for ip, events in sessions.items():
            ttps = set()
            creds = []
            cmds = []

            for ev in events:
                action = ev.get("action", "")
                if action in ACTION_MITRE:
                    ttps.add(ACTION_MITRE[action])

                payload = ev.get("payload") or ""
                service = ev.get("service", "")
                cred = ev.get("credential")

                if cred:
                    creds.append(cred)

                if service == "SSH" and action == "command_exec":
                    cmds.append(payload)
                    for pattern, tid, name in COMMAND_SIGS:
                        if re.search(pattern, payload, re.I):
                            ttps.add((tid, name))

                if service == "HTTP":
                    for pattern, tid, name in HTTP_SIGS:
                        if re.search(pattern, payload, re.I):
                            ttps.add((tid, name))

            profiles[ip] = {
                "ip": ip,
                "country": events[0].get("country", "Unknown"),
                "services_targeted": list({e["service"] for e in events}),
                "ttps": [{"id": t[0], "name": t[1]} for t in sorted(ttps)],
                "credentials_tried": creds,
                "commands_executed": cmds,
                "interaction_count": len(events),
                "threat_score": min(len(ttps)*10 + min(len(creds)*3,30) + min(len(cmds)*8,40), 100)
            }

        return profiles
