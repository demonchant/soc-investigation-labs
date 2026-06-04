"""
UEBA Detection Engine - Detects insider threat and compromised account indicators.
Checks: off-hours access, bulk data exfiltration, USB usage, impossible travel,
personal email with attachments, admin tool abuse, and new country access.
"""
import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

HIGH_RISK_COUNTRIES = {"RU","CN","KP","IR","SY","BY"}
BUSINESS_HOURS = (7, 19)  # 7 AM to 7 PM

MITRE = {
    "off_hours":      "T1078 - Valid Accounts (Off-Hours Access)",
    "bulk_download":  "T1005 - Data from Local System / Collection",
    "usb_exfil":      "T1052.001 - Exfiltration Over USB",
    "impossible_travel": "T1078 - Valid Accounts (Impossible Travel)",
    "personal_email": "T1048.003 - Exfiltration via Web Service (Email)",
    "admin_abuse":    "T1078.002 - Domain Account Privilege Abuse",
    "new_country":    "T1078 - Valid Accounts (New Geographic Location)",
}


class UEBAEngine:
    def __init__(self, profiles):
        self.profiles = profiles
        self.alerts = []

    def run(self, events):
        self._off_hours_access(events)
        self._bulk_data_download(events)
        self._usb_exfiltration(events)
        self._impossible_travel(events)
        self._personal_email_exfiltration(events)
        self._admin_tool_abuse(events)
        self._new_country_access(events)
        logger.info(f"UEBA detection complete. {len(self.alerts)} alert(s).")
        return self.alerts

    def _alert(self, title, severity, user, mitre, evidence):
        self.alerts.append({
            "title": title, "severity": severity,
            "user": user, "mitre_technique": mitre, "evidence": evidence
        })

    def _off_hours_access(self, events):
        for ev in events:
            hour = ev.get("hour", 12)
            if ev.get("action") == "login" and not (BUSINESS_HOURS[0] <= hour <= BUSINESS_HOURS[1]):
                self._alert("Off-Hours System Access", "medium", ev["user"],
                    MITRE["off_hours"],
                    {"hour": hour, "host": ev.get("host"),
                     "src_ip": ev.get("src_ip"), "timestamp": ev.get("timestamp")})

    def _bulk_data_download(self, events):
        for ev in events:
            files = ev.get("files_accessed", 0)
            data = ev.get("data_mb", 0)
            if files > 500 or data > 1000:
                self._alert("Bulk Data Access / Download", "critical", ev["user"],
                    MITRE["bulk_download"],
                    {"files_accessed": files, "data_mb": data,
                     "host": ev.get("host"), "timestamp": ev.get("timestamp")})

    def _usb_exfiltration(self, events):
        usb_users = set()
        for ev in events:
            if ev.get("action") == "usb_insert":
                usb_users.add(ev["user"])
        for ev in events:
            if ev.get("action") == "file_copy_to_usb" and ev["user"] in usb_users:
                self._alert("Data Copied to USB Storage Device", "critical", ev["user"],
                    MITRE["usb_exfil"],
                    {"files_accessed": ev.get("files_accessed"),
                     "data_mb": ev.get("data_mb"), "timestamp": ev.get("timestamp")})

    def _impossible_travel(self, events):
        user_countries = defaultdict(set)
        for ev in events:
            user_countries[ev["user"]].add(ev.get("country", ""))
        for user, countries in user_countries.items():
            if len(countries) > 1:
                self._alert("Impossible Travel / Multi-Country Access", "critical", user,
                    MITRE["impossible_travel"],
                    {"countries_seen": list(countries),
                     "high_risk_countries": list(countries & HIGH_RISK_COUNTRIES)})

    def _personal_email_exfiltration(self, events):
        free_domains = {"gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com"}
        for ev in events:
            if ev.get("action") == "email_send":
                recipient = ev.get("recipient","")
                domain = recipient.split("@")[-1].lower() if "@" in recipient else ""
                attachments = ev.get("attachments", 0)
                if domain in free_domains and attachments > 0:
                    self._alert("Sensitive Data Sent to Personal Email", "high", ev["user"],
                        MITRE["personal_email"],
                        {"recipient": recipient, "attachments": attachments,
                         "timestamp": ev.get("timestamp"), "host": ev.get("host")})

    def _admin_tool_abuse(self, events):
        for ev in events:
            if ev.get("action") in ("admin_tool_use","privilege_use"):
                tool = ev.get("tool") or ev.get("privilege","")
                self._alert("Privileged Tool / Right Usage Detected", "high", ev["user"],
                    MITRE["admin_abuse"],
                    {"action": ev.get("action"), "tool_or_privilege": tool,
                     "host": ev.get("host"), "timestamp": ev.get("timestamp")})

    def _new_country_access(self, events):
        for ev in events:
            country = ev.get("country","")
            if country in HIGH_RISK_COUNTRIES and ev.get("action") == "login":
                self._alert("Login from High-Risk Country", "critical", ev["user"],
                    MITRE["new_country"],
                    {"country": country, "src_ip": ev.get("src_ip"),
                     "host": ev.get("host"), "timestamp": ev.get("timestamp")})
