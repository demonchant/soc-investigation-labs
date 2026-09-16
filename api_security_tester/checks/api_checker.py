import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "broken_auth":  "T1078 - Valid Accounts (Broken Authentication)",
    "no_rate":      "T1498 - Network/API Abuse (No Rate Limiting)",
    "injection":    "T1190 - Exploit Public-Facing Application",
    "debug":        "T1082 - System Information Discovery (Debug Endpoint)",
    "bola":         "T1078 - Broken Object Level Authorization (IDOR)",
    "bulk_abuse":   "T1030 - Data Transfer Size Limits (Bulk Export Abuse)",
    "data_expose":  "T1530 - Data from Cloud Storage (Excessive Exposure)",
}

OWASP = {
    "broken_auth":  "OWASP API1:2023 - Broken Object Level Authorization",
    "no_rate":      "OWASP API4:2023 - Unrestricted Resource Consumption",
    "injection":    "OWASP API8:2023 - Security Misconfiguration / Injection",
    "debug":        "OWASP API8:2023 - Security Misconfiguration",
    "bola":         "OWASP API1:2023 - Broken Object Level Authorization",
    "bulk_abuse":   "OWASP API4:2023 - Unrestricted Resource Consumption",
}

SQL_PAT = re.compile(r"(\bOR\b|UNION|SELECT|--|;DROP|'\s*=)", re.I)
TRAV_PAT = re.compile(r"\.\./|/etc/passwd|/windows/system32", re.I)

class APIChecker:
    def __init__(self): self.findings = []

    def check_endpoints(self, endpoints):
        for ep in endpoints:
            self._missing_auth(ep); self._no_rate(ep)
            self._pii_no_validation(ep); self._debug_ep(ep)

    def check_requests(self, requests, endpoints):
        ep_map = {e["endpoint"]: e for e in endpoints}
        self._injection(requests); self._bulk_export(requests)
        self._idor(requests); self._unauth_access(requests, ep_map)

    def _f(self, cat, title, sev, ep, detail, mitre, owasp=None):
        f = {"category":cat,"title":title,"severity":sev,"endpoint":ep,
             "detail":detail,"mitre_technique":mitre}
        if owasp: f["owasp_category"] = owasp
        self.findings.append(f)

    def _missing_auth(self, ep):
        if not ep.get("auth_required") and ep.get("returns_pii"):
            self._f("auth","Unauthenticated Endpoint Returns PII","critical",ep["endpoint"],
                "No auth required but returns PII data.",MITRE["broken_auth"],OWASP["broken_auth"])
        elif not ep.get("auth_required") and "health" not in ep["endpoint"]:
            self._f("auth","Endpoint Missing Authentication","high",ep["endpoint"],
                "No authentication requirement on this endpoint.",MITRE["broken_auth"],OWASP["broken_auth"])

    def _no_rate(self, ep):
        if not ep.get("rate_limited") and ep.get("auth_required"):
            self._f("rate","Authenticated Endpoint Without Rate Limiting","high",ep["endpoint"],
                "No rate limiting — vulnerable to abuse.",MITRE["no_rate"],OWASP["no_rate"])

    def _pii_no_validation(self, ep):
        if ep.get("returns_pii") and not ep.get("input_validation"):
            self._f("data","PII Endpoint Missing Input Validation","high",ep["endpoint"],
                "Returns PII with no input validation — injection risk.",MITRE["data_expose"],OWASP["broken_auth"])

    def _debug_ep(self, ep):
        if "debug" in ep["endpoint"].lower() or "stack" in ep["endpoint"].lower():
            self._f("debug","Debug Endpoint Exposed","critical",ep["endpoint"],
                "Debug endpoint leaks internal implementation details.",MITRE["debug"],OWASP["debug"])

    def _injection(self, requests):
        for req in requests:
            url = req.get("endpoint","")
            payload = str(req.get("payload","") or "")
            combined = url + " " + payload
            if SQL_PAT.search(combined):
                self._f("injection","SQL Injection Attempt","critical",url,
                    "SQLi pattern from {}: {}".format(req["src_ip"],url[:80]),MITRE["injection"],OWASP["injection"])
            elif TRAV_PAT.search(combined):
                self._f("injection","Path Traversal Attempt","critical",url,
                    "Traversal pattern from {}: {}".format(req["src_ip"],str(payload)[:80]),MITRE["injection"],OWASP["injection"])

    def _bulk_export(self, requests):
        calls = defaultdict(list)
        for req in requests:
            if "export" in req.get("endpoint","").lower():
                calls[req.get("user_id","anon")].append(req)
        for user, reqs in calls.items():
            if len(reqs) >= 3:
                total = sum(r.get("response_size_kb",0)/1024 for r in reqs)
                self._f("bulk","Bulk Export Called Repeatedly","high",reqs[0]["endpoint"],
                    "User {} called export {} times. {:.1f}MB total.".format(user,len(reqs),total),
                    MITRE["bulk_abuse"],OWASP["no_rate"])

    def _idor(self, requests):
        user_eps = defaultdict(list)
        for req in requests:
            uid = req.get("user_id")
            if uid:
                parts = req["endpoint"].split("/")
                if parts and parts[-1].isdigit():
                    base = "/".join(parts[:-1])
                    user_eps[(uid,base)].append(int(parts[-1]))
        for (uid,base), ids in user_eps.items():
            if len(ids) >= 3:
                ids_s = sorted(ids)
                if ids_s == list(range(ids_s[0], ids_s[-1]+1)):
                    self._f("bola","Sequential IDOR/BOLA Enumeration","critical",
                        base+"/{id}","User {} accessed sequential IDs {}.".format(uid,ids_s),
                        MITRE["bola"],OWASP["bola"])

    def _unauth_access(self, requests, ep_map):
        for req in requests:
            ep = req.get("endpoint","").split("?")[0]
            ep_def = ep_map.get(ep)
            if ep_def and ep_def.get("auth_required") and not req.get("auth_header"):
                if req.get("status_code",0) == 200:
                    self._f("auth","Unauthenticated Access to Protected Endpoint Succeeded","critical",ep,
                        "No auth header from {} but got HTTP 200.".format(req["src_ip"]),
                        MITRE["broken_auth"],OWASP["broken_auth"])
