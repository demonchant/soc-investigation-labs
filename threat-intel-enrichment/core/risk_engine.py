HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}
MEDIUM_RISK_COUNTRIES = {"BY", "VE", "CU"}
CATEGORY_SCORES = {"malware": 20, "phishing": 15, "botnet": 15, "c2": 20, "ransomware": 25, "scanner": 10, "spam": 5}

class RiskEngine:
    def calculate(self, data):
        score = 0
        rep = data.get("reputation", "clean")
        if rep == "malicious": score += 60
        elif rep == "suspicious": score += 35
        else: score += 5
        score += min(len(data.get("sources", [])) * 5, 20)
        geo = data.get("geo", "")
        if geo in HIGH_RISK_COUNTRIES: score += 15
        elif geo in MEDIUM_RISK_COUNTRIES: score += 8
        for cat in data.get("categories", []):
            score += CATEGORY_SCORES.get(cat.lower(), 0)
        return min(score, 100)
