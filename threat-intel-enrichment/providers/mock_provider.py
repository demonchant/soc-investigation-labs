import random

class MockProvider:
    REPUTATIONS = ["clean", "clean", "suspicious", "malicious"]
    COUNTRIES = ["US", "DE", "NG", "GB", "RU", "CN", "FR", "KP", "BR", "IN"]
    ALL_SOURCES = ["VirusTotal", "AbuseIPDB", "Shodan", "AlienVault OTX", "InternalDB", "ThreatFox"]
    CATEGORIES = ["malware", "phishing", "botnet", "c2", "scanner", "spam", "ransomware"]

    def _generate(self, seed):
        r = random.Random(seed)
        rep = r.choice(self.REPUTATIONS)
        sc = r.randint(1, 4)
        cc = r.randint(0, 2) if rep != "clean" else 0
        return {
            "reputation": rep,
            "geo": r.choice(self.COUNTRIES),
            "sources": r.sample(self.ALL_SOURCES, k=sc),
            "categories": r.sample(self.CATEGORIES, k=cc) if cc else []
        }

    def lookup_ip(self, ip): return self._generate(ip)
    def lookup_domain(self, domain): return self._generate(domain)
    def lookup_hash(self, h): return self._generate(h)
