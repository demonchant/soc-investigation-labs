"""
Content Analyser — Scans email body for urgency language, credential harvesting
URLs, malicious attachment types, financial fraud patterns, and BEC indicators.
"""
import re, logging
logger = logging.getLogger(__name__)

URGENCY_PATTERNS = [
    r"(?i)(account.{0,15}(suspend|terminat|block|comprom))",
    r"(?i)(verify.{0,15}(immediately|now|urgent|within 24))",
    r"(?i)(action.{0,10}required)",
    r"(?i)(expires? in \d+ hours?)",
    r"(?i)(unusual.{0,15}(activity|sign.in|access))",
]

CREDENTIAL_HARVEST_PATTERNS = [
    r"(?i)(click here to (verify|confirm|update|login|reset))",
    r"(?i)(enter your (password|credentials|username|details))",
    r"(?i)(your account (has been|will be|is))",
]

BEC_PATTERNS = [
    r"(?i)(wire transfer|bank transfer|urgent payment)",
    r"(?i)(confidential.{0,20}(do not|don't).{0,20}(discuss|share|tell))",
    r"(?i)(board meeting|in a meeting|can only (email|communicate))",
    r"(?i)(IBAN|sort code|account number|swift code)",
]

SUSPICIOUS_URL_PATTERNS = [
    r"(?i)(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # IP-based URL
    r"(?i)(verify|login|secure|account).{0,20}\.(ru|cn|kp|tk|ml|ga|cf|gq)/",
    r"(?i)bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly",  # URL shorteners
    r"(?i)(token|auth|verify)=[a-zA-Z0-9]{8,}",   # token params
]

MALICIOUS_EXTENSIONS = {".exe",".scr",".bat",".cmd",".vbs",".js",".jar",".ps1",".hta"}
MACRO_TYPES = {"application/vnd.ms-word.document.macroEnabled",
               "application/vnd.ms-excel.sheet.macroEnabled",
               "application/vnd.ms-powerpoint.presentation.macroEnabled"}


class ContentAnalyser:
    def analyse(self, email):
        findings = []
        score = 0
        body = email.get("body","")

        # Urgency language
        urgency_hits = [p for p in URGENCY_PATTERNS if re.search(p, body)]
        if urgency_hits:
            findings.append({"check":"Urgency Language","result":"DETECTED",
                "detail":f"{len(urgency_hits)} urgency pattern(s) found","score":15})
            score += 15

        # Credential harvesting
        cred_hits = [p for p in CREDENTIAL_HARVEST_PATTERNS if re.search(p, body)]
        if cred_hits:
            findings.append({"check":"Credential Harvesting Language","result":"DETECTED",
                "detail":f"{len(cred_hits)} harvesting pattern(s) found","score":25})
            score += 25

        # BEC / financial fraud
        bec_hits = [p for p in BEC_PATTERNS if re.search(p, body)]
        if bec_hits:
            findings.append({"check":"BEC / Financial Fraud Pattern","result":"DETECTED",
                "detail":f"{len(bec_hits)} BEC indicator(s) found — possible CEO fraud","score":40})
            score += 40

        # Suspicious URLs
        urls = email.get("urls", [])
        for url in urls:
            url_hits = [p for p in SUSPICIOUS_URL_PATTERNS if re.search(p, url)]
            if url_hits:
                findings.append({"check":"Suspicious URL","result":"MALICIOUS",
                    "detail":f"URL flagged: {url[:80]}","score":35})
                score += 35
                break

        # Attachments
        for att in email.get("attachments",[]):
            ext = "." + att["name"].split(".")[-1].lower() if "." in att["name"] else ""
            att_type = att.get("type","")
            if ext in MALICIOUS_EXTENSIONS:
                findings.append({"check":"Malicious Attachment Extension","result":"CRITICAL",
                    "detail":f"Dangerous file type: {att['name']}","score":50})
                score += 50
            elif att_type in MACRO_TYPES:
                findings.append({"check":"Macro-Enabled Document","result":"HIGH",
                    "detail":f"Macro-enabled Office file: {att['name']}","score":40})
                score += 40

        return findings, min(score, 100)
