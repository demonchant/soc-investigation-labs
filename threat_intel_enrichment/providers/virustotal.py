import os, requests, logging
logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalProvider:
    def __init__(self):
        self.api_key = os.environ.get("VT_API_KEY", "")
        if not self.api_key:
            logger.warning("VT_API_KEY not set.")
        self.headers = {"x-apikey": self.api_key}

    def lookup_ip(self, ip): return self._fetch(f"{VT_BASE}/ip_addresses/{ip}")
    def lookup_domain(self, d): return self._fetch(f"{VT_BASE}/domains/{d}")
    def lookup_hash(self, h): return self._fetch(f"{VT_BASE}/files/{h}")

    def _fetch(self, url):
        try:
            r = requests.get(url, headers=self.headers, timeout=10)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
        return None
