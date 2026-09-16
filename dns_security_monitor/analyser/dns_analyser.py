import re, math, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

TYPOSQUAT = [
    (re.compile(r"paypa[l1]", re.I), "PayPal"),
    (re.compile(r"micros[o0]ft", re.I), "Microsoft"),
    (re.compile(r"g[o0]{2}gle", re.I), "Google"),
    (re.compile(r"binanse|binanc3", re.I), "Binance"),
]

MITRE = {
    "tunnel": "T1071.004 - DNS Tunneling",
    "typo":   "T1566.002 - Spearphishing Link (typosquat)",
    "dga":    "T1568.002 - Domain Generation Algorithm",
    "malip":  "T1071 - C2 via malicious DNS response",
    "hient":  "T1071.004 - High-Entropy C2 Subdomain",
}

def entropy(s):
    if not s: return 0
    freq = {c: s.count(c)/len(s) for c in set(s)}
    return -sum(p*math.log2(p) for p in freq.values())

class DNSAnalyser:
    def __init__(self, threat_ips):
        self.threat_ips = threat_ips
        self.alerts = []

    def run(self, events):
        self._tunneling(events)
        self._typosquat(events)
        self._dga(events)
        self._malicious_response(events)
        self._high_entropy(events)
        return self.alerts

    def _a(self, title, sev, src, mitre, ev):
        self.alerts.append({"title":title,"severity":sev,"src_ip":src,"mitre_technique":mitre,"evidence":ev})

    def _tunneling(self, events):
        for ev in events:
            q = ev.get("query","")
            if ev.get("qtype")=="TXT" and len(q)>40 and entropy(q.split(".")[0])>3.5:
                self._a("DNS Tunneling — Oversized TXT Query","high",ev["src_ip"],MITRE["tunnel"],
                    {"query":q[:80],"length":len(q),"entropy":round(entropy(q.split(".")[0]),2)})

    def _typosquat(self, events):
        for ev in events:
            q = ev.get("query","").lower()
            for pat, brand in TYPOSQUAT:
                if pat.search(q) and brand.lower() not in q:
                    self._a("Typosquat Domain — Impersonating "+brand,"high",ev["src_ip"],MITRE["typo"],
                        {"query":q,"brand_spoofed":brand,"response_ip":ev.get("response","")})
                    break

    def _dga(self, events):
        nx = defaultdict(list)
        for ev in events:
            if ev.get("response_code")=="NXDOMAIN":
                sub = ev["query"].split(".")[0]
                if entropy(sub)>3.2 and len(sub)>6:
                    nx[ev["src_ip"]].append(ev["query"])
        for src, qs in nx.items():
            if len(qs)>=3:
                self._a("DGA Activity — Repeated NXDOMAIN for Random Domains","critical",src,MITRE["dga"],
                    {"nxdomain_count":len(qs),"sample":qs[:5]})

    def _malicious_response(self, events):
        for ev in events:
            rip = ev.get("response","")
            if rip in self.threat_ips:
                self._a("DNS Response Points to Known Malicious IP","critical",ev["src_ip"],MITRE["malip"],
                    {"query":ev["query"],"response_ip":rip,"label":self.threat_ips[rip]})

    def _high_entropy(self, events):
        for ev in events:
            parts = ev.get("query","").split(".")
            if len(parts)>=3:
                sub = parts[0]
                ent = entropy(sub)
                if ent>3.8 and len(sub)>20:
                    self._a("High-Entropy Subdomain — Possible C2 Encoding","high",ev["src_ip"],MITRE["hient"],
                        {"subdomain":sub[:60],"entropy":round(ent,2)})
