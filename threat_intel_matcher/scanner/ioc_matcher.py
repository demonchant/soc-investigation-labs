import re, logging
logger = logging.getLogger(__name__)

MITRE = {
    "ip_c2":     "T1071.001 - Application Layer Protocol: C2 via Web",
    "ip_scan":   "T1595.001 - Active Scanning: Scanning IP Blocks",
    "domain":    "T1566.002 - Phishing: Spearphishing Link",
    "hash":      "T1204.002 - User Execution: Malicious File",
    "url":       "T1566.002 - Phishing: Spearphishing Link",
    "email":     "T1566.001 - Phishing: Spearphishing Attachment",
    "tor":       "T1090.003 - Proxy: Multi-hop Proxy (Tor exit)",
    "botnet":    "T1583.005 - Acquire Infrastructure: Botnet",
}

THREAT_CATEGORIES = {
    "c2":           ("C2 Server",      "critical"),
    "malware":      ("Malware Host",   "critical"),
    "phishing":     ("Phishing",       "high"),
    "botnet":       ("Botnet Node",    "high"),
    "scanner":      ("Mass Scanner",   "medium"),
    "tor_exit":     ("Tor Exit Node",  "medium"),
    "spam":         ("Spam Source",    "low"),
}

class IOCMatcher:
    def __init__(self): self.findings = []

    def match_all(self, data):
        feed   = {ioc["value"].lower(): ioc for ioc in data.get("threat_feed", [])}
        events = data.get("log_events", [])
        for ev in events:
            self._check_event(ev, feed)
        return self.findings

    def _f(self, ev_id, src, ioc_val, ioc_type, threat, conf, sev, detail, mitre, rec):
        self.findings.append({
            "event_id": ev_id, "source": src, "matched_ioc": ioc_val,
            "ioc_type": ioc_type, "threat_category": threat, "confidence": conf,
            "severity": sev, "detail": detail, "mitre_technique": mitre,
            "recommendation": rec
        })

    def _check_event(self, ev, feed):
        eid = ev.get("event_id", "?")
        src = ev.get("source_ip", "")
        dst = ev.get("dest_ip", ev.get("dest_domain", ""))
        url = ev.get("url", "")
        fhash = ev.get("file_hash", "")
        sender = ev.get("email_sender", "")

        candidates = [
            (src,    "ip"),
            (dst,    "ip" if re.match(r"\d+\.\d+\.\d+\.\d+", dst) else "domain"),
            (url,    "url"),
            (fhash,  "hash"),
            (sender, "email"),
        ]

        for value, ioc_type in candidates:
            if not value:
                continue
            key = value.lower()
            # exact match
            if key in feed:
                entry   = feed[key]
                cat     = entry.get("category", "unknown")
                conf    = entry.get("confidence", 50)
                label, default_sev = THREAT_CATEGORIES.get(cat, ("Unknown Threat", "medium"))
                sev     = "critical" if conf >= 90 else default_sev
                mitre   = MITRE.get("ip_c2" if ioc_type == "ip" else ioc_type,
                                    MITRE.get(cat, "T1071"))
                self._f(eid, src or dst, value, ioc_type, label, conf, sev,
                    "{} '{}' matched threat feed entry: {} (conf {}%). First seen: {}.".format(
                        ioc_type.upper(), value, label, conf, entry.get("first_seen","unknown")),
                    mitre,
                    "Block {} at perimeter. Investigate all sessions involving this {}. "
                    "Correlate with endpoint telemetry.".format(value, ioc_type))
                continue

            # domain substring match (catch subdomains of malicious apex)
            if ioc_type == "domain":
                for feed_val, entry in feed.items():
                    if feed_val in key and entry.get("ioc_type") == "domain":
                        self._f(eid, src, value, "subdomain",
                            THREAT_CATEGORIES.get(entry.get("category","unknown"), ("Unknown","medium"))[0],
                            entry.get("confidence",40) - 10, "medium",
                            "Domain '{}' is subdomain of known-malicious apex '{}'.".format(value, feed_val),
                            MITRE["domain"],
                            "Block apex domain {}. Investigate DNS queries.".format(feed_val))
                        break
