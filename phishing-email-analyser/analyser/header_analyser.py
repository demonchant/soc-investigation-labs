"""
Header Analyser — Evaluates SPF/DKIM/DMARC authentication results,
sender/display-name mismatches, reply-to anomalies, and sending IP risk.
"""
import re, logging
logger = logging.getLogger(__name__)

HIGH_RISK_COUNTRIES = {"RU","CN","KP","IR","SY","BY","NG"}
FREE_MAIL = {"gmail.com","protonmail.com","yahoo.com","hotmail.com","outlook.com"}


class HeaderAnalyser:
    def analyse(self, email):
        findings = []
        score = 0

        # SPF / DKIM / DMARC
        spf = email.get("spf","")
        dkim = email.get("dkim","")
        dmarc = email.get("dmarc","")

        if spf in ("FAIL","SOFTFAIL"):
            s = 25 if spf == "FAIL" else 10
            findings.append({"check":"SPF","result":spf,"detail":"Sender IP not authorised by domain SPF record","score":s})
            score += s
        if dkim in ("FAIL","NONE"):
            s = 20 if dkim == "FAIL" else 10
            findings.append({"check":"DKIM","result":dkim,"detail":"Email signature missing or invalid","score":s})
            score += s
        if dmarc in ("FAIL","NONE"):
            s = 20 if dmarc == "FAIL" else 5
            findings.append({"check":"DMARC","result":dmarc,"detail":"DMARC policy check failed — domain alignment issue","score":s})
            score += s

        # Sender domain vs display name mismatch
        from_addr = email.get("from","")
        from_display = email.get("from_display","")
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        display_brand = self._extract_brand(from_display)
        if display_brand and display_brand not in from_domain:
            findings.append({"check":"Display Name Spoofing","result":"MISMATCH",
                "detail":f"Display '{from_display}' does not match sending domain '{from_domain}'","score":30})
            score += 30

        # Reply-To mismatch
        reply_to = email.get("reply_to","")
        if reply_to and reply_to != from_addr:
            reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if reply_domain != from_domain:
                pts = 20
                if reply_domain in FREE_MAIL:
                    pts = 30
                findings.append({"check":"Reply-To Mismatch","result":"SUSPICIOUS",
                    "detail":f"Reply-To '{reply_to}' differs from sender '{from_addr}'","score":pts})
                score += pts

        # High-risk sending IP country
        country = email.get("ip_country","")
        if country in HIGH_RISK_COUNTRIES:
            findings.append({"check":"Sending IP Country","result":country,
                "detail":f"Email originated from high-risk country: {country}","score":15})
            score += 15

        # Domain typosquat check
        typo = self._check_typosquat(from_domain)
        if typo:
            findings.append({"check":"Typosquatting","result":"DETECTED",
                "detail":f"Domain '{from_domain}' appears to spoof '{typo}'","score":35})
            score += 35

        return findings, min(score, 100)

    def _extract_brand(self, display_name):
        known = ["microsoft","google","linkedin","github","paypal","amazon","apple","dropbox","docusign"]
        for b in known:
            if b.lower() in display_name.lower():
                return b
        return None

    def _check_typosquat(self, domain):
        legit = {
            "microsoft.com":"micros0ft|m1crosoft|microsooft|microsofft",
            "google.com":"g00gle|gooogle|googlle",
            "paypal.com":"paypa1|paypall|paypa-l",
            "linkedin.com":"linkedln|1inkedin",
        }
        for legit_domain, patterns in legit.items():
            if re.search(patterns, domain, re.I) and domain != legit_domain:
                return legit_domain
        return None
