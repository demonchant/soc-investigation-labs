"""IOC Extractor — Extracts IPs, URLs, dropped files, credentials, web shells."""
import re
import logging
logger = logging.getLogger(__name__)

URL_PAT = re.compile(r'https?://[^\s\'"<>]+', re.I)
PATH_PAT = re.compile(r'(/tmp/\S+|/var/www/\S+)', re.I)


class IOCExtractor:
    def extract(self, sessions):
        iocs = {"malicious_ips": [], "malicious_urls": [], "dropped_files": [],
                "compromised_credentials": [], "web_shells": []}

        for ip, events in sessions.items():
            iocs["malicious_ips"].append(ip)
            for ev in events:
                payload = ev.get("payload") or ""
                cred = ev.get("credential")

                for url in URL_PAT.findall(payload):
                    if url not in iocs["malicious_urls"]:
                        iocs["malicious_urls"].append(url)

                for path in PATH_PAT.findall(payload):
                    if path not in iocs["dropped_files"]:
                        iocs["dropped_files"].append(path)

                if cred and ev.get("action") == "auth_success":
                    if cred not in iocs["compromised_credentials"]:
                        iocs["compromised_credentials"].append(cred)

                if re.search(r'shell\.php|cmd\.php|c99|r57', payload, re.I):
                    iocs["web_shells"].append({"attacker_ip": ip, "path": payload})

        total = sum(len(v) for v in iocs.values())
        logger.info("Extracted " + str(total) + " IOCs.")
        return iocs
