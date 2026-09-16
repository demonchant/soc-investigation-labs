"""Event Classifier — Tags raw log entries with correlation event types."""
import re

HIGH_RISK_IPS = {"185.220.101.47","194.165.16.72","45.142.212.100","92.63.197.50"}
INTERNAL_SERVICES = re.compile(r"(admin|vpn|mail|dc|ldap|exchange|sharepoint|fileserver)\.", re.I)

def classify(log):
    tags = []
    src = log.get("src_ip","")
    ev = log.get("event","")
    source = log.get("source","")

    if source == "dns" and INTERNAL_SERVICES.search(log.get("query","")):
        tags.append("dns_internal_recon")

    if ev == "logon_fail":
        tags.append("logon_fail")
        tags.append("logon_attempt")

    if ev == "logon_success":
        tags.append("logon_success")
        tags.append("logon_attempt")

    if source == "firewall" and log.get("dst_ip","") in HIGH_RISK_IPS:
        tags.append("c2_connection")

    if source == "firewall" and log.get("bytes",0) > 1000000:
        tags.append("large_outbound")

    if source == "proxy" and log.get("dst_url","") and any(ip in log.get("dst_url","") for ip in HIGH_RISK_IPS):
        tags.append("malicious_download")

    if ev == "process_create" and re.search(r"vssadmin.+delete|wmic.+shadow|bcdedit", log.get("cmdline",""), re.I):
        tags.append("ransomware_indicator")

    log["_tags"] = tags
    return log
