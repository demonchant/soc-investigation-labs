"""
Network Baseline Anomaly Detector
Builds per-host statistical baselines from historical network flows,
then flags deviations: volume spikes, new destinations, port anomalies,
unusual protocols, and east-west lateral movement indicators.
"""
import statistics, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "exfil":   "T1048 - Exfiltration Over Alternative Protocol",
    "c2":      "T1071 - Application Layer Protocol (unusual outbound)",
    "recon":   "T1046 - Network Service Discovery (port anomaly)",
    "lateral": "T1021 - Remote Services (internal traffic anomaly)",
    "newdest": "T1071.001 - Web Protocols (new external destination)",
}

INTERNAL_RANGES = ("10.","172.16.","172.17.","172.18.","172.19.","172.20.",
                   "172.21.","172.22.","172.23.","172.24.","172.25.","172.26.",
                   "172.27.","172.28.","172.29.","172.30.","172.31.","192.168.")

SPIKE_MULT      = 5.0
NEW_DEST_BYTES  = 10_000
PORT_LIMIT      = 10
UNUSUAL_PROTOS  = {"TELNET","FTP","IRC","VNC"}

def is_internal(ip): return any(ip.startswith(r) for r in INTERNAL_RANGES)

class NetworkBaselineDetector:
    def __init__(self): self.findings = []

    def detect_all(self, data):
        baseline = self._build_baseline(data.get("baseline_flows",[]))
        current  = self._aggregate_current(data.get("current_flows",[]))
        self._compare(baseline, current)
        return self.findings

    def _f(self, host, title, sev, detail, mitre, rec):
        self.findings.append({"host":host,"title":title,"severity":sev,
            "detail":detail,"mitre_technique":mitre,"recommendation":rec})

    def _build_baseline(self, flows):
        hd = defaultdict(lambda:{"ext_bytes":[],"int_bytes":[],"ports":set(),
                                  "ext_dsts":set(),"protos":set()})
        for f in flows:
            src=f.get("src_ip",""); dst=f.get("dst_ip","")
            d=hd[src]; d["ports"].add(f.get("dst_port",0))
            d["protos"].add(f.get("protocol",""))
            bt=f.get("bytes_total",0)
            if is_internal(dst): d["int_bytes"].append(bt)
            else: d["ext_bytes"].append(bt); d["ext_dsts"].add(dst)
        base={}
        for host,d in hd.items():
            ext=d["ext_bytes"] or [0]; int_b=d["int_bytes"] or [0]
            base[host]={"avg_ext":statistics.mean(ext),
                        "avg_int":statistics.mean(int_b),
                        "known_ports":set(d["ports"]),
                        "known_ext_dsts":set(d["ext_dsts"]),
                        "known_protos":set(d["protos"])}
        return base

    def _aggregate_current(self, flows):
        hd=defaultdict(lambda:{"ext_bytes":0,"int_bytes":0,"ports":set(),
                                "ext_dsts":defaultdict(int),"protos":set()})
        for f in flows:
            src=f.get("src_ip",""); dst=f.get("dst_ip","")
            bt=f.get("bytes_total",0); d=hd[src]
            d["ports"].add(f.get("dst_port",0))
            d["protos"].add(f.get("protocol",""))
            if is_internal(dst): d["int_bytes"]+=bt
            else: d["ext_bytes"]+=bt; d["ext_dsts"][dst]+=bt
        return dict(hd)

    def _compare(self, baseline, current):
        for host, curr in current.items():
            base = baseline.get(host)
            # External volume spike
            if base and base["avg_ext"] > 0:
                ratio = curr["ext_bytes"] / base["avg_ext"]
                if ratio > SPIKE_MULT:
                    sev = "critical" if ratio > 20 else "high"
                    self._f(host,"External Traffic Spike: {:.1f}x baseline ({:.1f}MB)".format(
                        ratio, curr["ext_bytes"]/1_000_000),sev,
                        "Host '{}' sent {:.1f}MB externally — {:.1f}x above {:.1f}MB baseline. "
                        "Possible data exfiltration.".format(
                            host,curr["ext_bytes"]/1_000_000,ratio,base["avg_ext"]/1_000_000),
                        MITRE["exfil"],
                        "Investigate destination IPs. Check for archive/compression tools "
                        "run before this traffic. Correlate with DLP alerts.")
            # New external destinations
            if base:
                new_dsts={d for d,b in curr["ext_dsts"].items()
                          if d not in base["known_ext_dsts"] and b > NEW_DEST_BYTES}
                if new_dsts:
                    top=sorted(new_dsts,key=lambda d:-curr["ext_dsts"][d])[:3]
                    self._f(host,"New External Destinations: {} never-before-seen".format(len(new_dsts)),"medium",
                        "Host '{}' contacted {} new external destinations with significant traffic. "
                        "Top new: {}.".format(host,len(new_dsts),
                            ", ".join("{} ({:.0f}KB)".format(d,curr["ext_dsts"][d]/1000) for d in top)),
                        MITRE["newdest"],
                        "Verify these destinations are legitimate. Check domain reputation. "
                        "New high-traffic destinations = potential C2 or exfil channel.")
            # Port anomaly
            n_ports = len(curr["ports"])
            if n_ports > PORT_LIMIT:
                known = base["known_ports"] if base else set()
                new_p = curr["ports"] - known
                self._f(host,"Port Anomaly: {} unique ports ({} new)".format(n_ports,len(new_p)),"high",
                    "Host '{}' contacted {} unique destination ports ({} not in baseline). "
                    "Pattern consistent with port scanning or lateral movement recon.".format(
                        host,n_ports,len(new_p)),
                    MITRE["recon"],
                    "Check if host is running a scanner. If unexpected, investigate for "
                    "compromise and lateral movement attempt.")
            # Unusual protocols
            if base:
                unusual = {p for p in (curr["protos"]-base["known_protos"])
                           if p.upper() in UNUSUAL_PROTOS}
                if unusual:
                    self._f(host,"Unusual Protocol Detected: {}".format(", ".join(unusual)),"high",
                        "Host '{}' used cleartext/abused protocol(s) {} not seen in baseline.".format(
                            host,", ".join(unusual)),
                        MITRE["c2"],
                        "Investigate why this protocol appeared. Telnet/FTP/IRC should be blocked "
                        "at perimeter. These protocols are commonly used for C2.")
            # East-west spike
            if base and base["avg_int"] > 0:
                ratio = curr["int_bytes"] / base["avg_int"]
                if ratio > SPIKE_MULT:
                    self._f(host,"Internal Traffic Spike: {:.1f}x baseline".format(ratio),"high",
                        "Host '{}' internal traffic is {:.1f}x above baseline ({:.1f}MB vs {:.1f}MB avg). "
                        "Could indicate lateral movement, data staging, or ransomware spreading.".format(
                            host,ratio,curr["int_bytes"]/1_000_000,base["avg_int"]/1_000_000),
                        MITRE["lateral"],
                        "Check which internal hosts are being accessed. Correlate with auth logs. "
                        "Investigate for ransomware pre-encryption staging.")
