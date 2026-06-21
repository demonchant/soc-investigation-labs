import re, logging, itertools
from collections import defaultdict
from datetime import datetime
logger = logging.getLogger(__name__)

MITRE = {
    "cluster":   "Diamond Model - Infrastructure Overlap Correlation",
    "ttp":       "MITRE ATT&CK - TTP Pattern Matching",
    "temporal":  "Campaign Timeline Correlation",
    "actor":     "Threat Actor Attribution",
}

# Known APT/crimeware TTP signatures — simplified fingerprints for clustering
ACTOR_PROFILES = {
    "APT29-like":   {"ttps": {"T1071.001","T1059.001","T1218.005","T1003.001"},
                      "infra_tlds": {".com",".net"}, "tooling": {"cobalt strike","powershell empire"}},
    "FIN7-like":     {"ttps": {"T1566.001","T1059.005","T1547.001","T1071.001"},
                      "infra_tlds": {".com",".info"}, "tooling": {"carbanak","griffon"}},
    "LockBit-affiliate": {"ttps": {"T1486","T1490","T1021.002","T1059.001"},
                      "infra_tlds": {".onion",".com"}, "tooling": {"lockbit","cobalt strike"}},
    "Generic-eCrime": {"ttps": {"T1110.004","T1566.002","T1059.003"},
                      "infra_tlds": {".xyz",".top",".online"}, "tooling": {"metasploit","redline stealer"}},
}

class CampaignTracker:
    def __init__(self): self.findings = []

    def analyze_all(self, data):
        incidents = data.get("incidents", [])
        self._cluster_by_infrastructure(incidents)
        self._cluster_by_ttp(incidents)
        self._attribute_actors(incidents)
        return self.findings

    def _f(self, title, sev, detail, mitre, rec, incident_ids=None):
        self.findings.append({"title": title, "severity": sev, "detail": detail,
            "mitre_technique": mitre, "recommendation": rec,
            "related_incidents": incident_ids or []})

    def _cluster_by_infrastructure(self, incidents):
        """Group incidents sharing IPs, domains, or hash families."""
        ip_map     = defaultdict(list)
        domain_map = defaultdict(list)
        hash_map   = defaultdict(list)

        for inc in incidents:
            iid = inc["incident_id"]
            for ip in inc.get("iocs", {}).get("ips", []):
                ip_map[ip].append(iid)
            for d in inc.get("iocs", {}).get("domains", []):
                apex = ".".join(d.split(".")[-2:])
                domain_map[apex].append(iid)
            for h in inc.get("iocs", {}).get("hashes", []):
                hash_map[h[:16]].append(iid)  # hash prefix = family proxy

        for ip, ids in ip_map.items():
            if len(set(ids)) >= 2:
                self._f("Shared Infrastructure: IP {} Links {} Incidents".format(ip, len(set(ids))),
                    "high",
                    "IP {} appears across incidents {} — same operator likely reused infrastructure.".format(
                        ip, ", ".join(sorted(set(ids)))),
                    MITRE["cluster"],
                    "Merge these incidents into a single campaign tracking ticket. "
                    "Pivot on this IP across all historical logs for additional victims.",
                    sorted(set(ids)))

        for domain, ids in domain_map.items():
            if len(set(ids)) >= 2:
                self._f("Shared Infrastructure: Domain Family '{}' Links {} Incidents".format(
                    domain, len(set(ids))), "high",
                    "Apex domain {} (or subdomains) seen in incidents {}.".format(
                        domain, ", ".join(sorted(set(ids)))),
                    MITRE["cluster"],
                    "Investigate domain registration history. Check for sibling domains "
                    "via passive DNS / WHOIS pivoting.",
                    sorted(set(ids)))

        for hpfx, ids in hash_map.items():
            if len(set(ids)) >= 2:
                self._f("Shared Tooling: Hash Family '{}…' Links {} Incidents".format(
                    hpfx, len(set(ids))), "critical",
                    "File hash prefix {} appears in {} — same malware build or builder used.".format(
                        hpfx, ", ".join(sorted(set(ids)))),
                    MITRE["cluster"],
                    "High-confidence campaign link. Submit sample for malware family classification. "
                    "Search EDR fleet-wide for this hash.",
                    sorted(set(ids)))

    def _cluster_by_ttp(self, incidents):
        """Group incidents sharing 3+ identical MITRE techniques (behavioral fingerprint)."""
        pairs = itertools.combinations(incidents, 2)
        seen = set()
        for inc_a, inc_b in pairs:
            ttps_a = set(inc_a.get("mitre_techniques", []))
            ttps_b = set(inc_b.get("mitre_techniques", []))
            overlap = ttps_a & ttps_b
            key = tuple(sorted([inc_a["incident_id"], inc_b["incident_id"]]))
            if len(overlap) >= 3 and key not in seen:
                seen.add(key)
                similarity = len(overlap) / len(ttps_a | ttps_b) if (ttps_a | ttps_b) else 0
                sev = "critical" if similarity >= 0.6 else "high"
                self._f("TTP Overlap: {} & {} Share {} Techniques ({:.0%} similarity)".format(
                    inc_a["incident_id"], inc_b["incident_id"], len(overlap), similarity),
                    sev,
                    "Shared techniques: {}. This behavioral fingerprint suggests common "
                    "playbook, tooling, or operator.".format(", ".join(sorted(overlap))),
                    MITRE["ttp"],
                    "Treat as same campaign pending infrastructure confirmation. "
                    "Compare full kill chains for procedural-level match.",
                    [inc_a["incident_id"], inc_b["incident_id"]])

    def _attribute_actors(self, incidents):
        """Score each incident against known actor profiles for tentative attribution."""
        for inc in incidents:
            iid = inc["incident_id"]
            ttps = set(inc.get("mitre_techniques", []))
            tooling = set(t.lower() for t in inc.get("tooling_observed", []))
            domains = inc.get("iocs", {}).get("domains", [])
            tlds = {"." + d.split(".")[-1] for d in domains}

            best_actor, best_score = None, 0
            for actor, profile in ACTOR_PROFILES.items():
                ttp_overlap = len(ttps & profile["ttps"])
                tool_overlap = len(tooling & profile["tooling"])
                tld_overlap = len(tlds & profile["infra_tlds"])
                score = ttp_overlap * 20 + tool_overlap * 30 + tld_overlap * 10
                if score > best_score:
                    best_score, best_actor = score, actor

            if best_score >= 40:
                confidence = min(best_score, 100)
                sev = "critical" if confidence >= 70 else "medium"
                self._f("Tentative Attribution: {} Matches Profile '{}' ({}% confidence)".format(
                    iid, best_actor, confidence), sev,
                    "Incident {} shares TTPs/tooling/infrastructure patterns consistent with "
                    "{}. This is a HYPOTHESIS, not confirmed attribution.".format(iid, best_actor),
                    MITRE["actor"],
                    "Do NOT brief attribution as fact. Use to prioritize hunt hypotheses and "
                    "check threat intel feeds for this actor's recent reported TTPs.",
                    [iid])
