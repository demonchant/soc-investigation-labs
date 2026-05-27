"""
Anomaly Detection Engine - Statistical + rule-based hybrid.
Detects: large transfers, port scanning, C2 beaconing, DNS tunneling,
SMB lateral movement, high-risk ports, Z-score volume deviations.
MITRE ATT&CK mapped.
"""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

MITRE = {
    "data_exfil":     "T1048 - Exfiltration Over Alternative Protocol",
    "port_scan":      "T1046 - Network Service Discovery",
    "c2_beacon":      "T1071 - Application Layer Protocol (C2)",
    "dns_tunnel":     "T1071.004 - DNS Tunneling",
    "lateral_smb":    "T1021.002 - SMB/Windows Admin Shares",
    "high_risk_port": "T1572 - Protocol Tunneling",
    "vol_anomaly":    "T1030 - Data Transfer Size Limits Bypass",
}

Z_THRESH = 2.5


class AnomalyEngine:
    def __init__(self, profiles):
        self.profiles = profiles
        self.alerts = []

    def run(self, flows):
        self._large_transfers(flows)
        self._port_scan(flows)
        self._c2_beaconing(flows)
        self._dns_tunneling(flows)
        self._lateral_smb(flows)
        self._high_risk_ports(flows)
        self._zscore_volume(flows)
        logger.info("Detection complete. " + str(len(self.alerts)) + " alert(s).")
        return self.alerts

    def _alert(self, title, severity, src, mitre, evidence):
        self.alerts.append({
            "title": title, "severity": severity,
            "src_ip": src, "mitre_technique": mitre, "evidence": evidence
        })

    def _large_transfers(self, flows):
        for f in flows:
            if f["bytes_sent"] > 200000:
                self._alert("Large Outbound Data Transfer", "high", f["src_ip"],
                    MITRE["data_exfil"],
                    {"bytes_sent": f["bytes_sent"], "dst_ip": f["dst_ip"], "port": f["dst_port"]})

    def _port_scan(self, flows):
        sp = defaultdict(set)
        sd = defaultdict(set)
        for f in flows:
            sp[f["src_ip"]].add(f["dst_port"])
            sd[f["src_ip"]].add(f["dst_ip"])
        for ip in sp:
            if len(sp[ip]) >= 5 or len(sd[ip]) >= 5:
                self._alert("Network Port / Host Scan Detected", "medium", ip,
                    MITRE["port_scan"],
                    {"unique_ports": len(sp[ip]), "unique_hosts": len(sd[ip])})

    def _c2_beaconing(self, flows):
        sessions = defaultdict(list)
        for f in flows:
            sessions[(f["src_ip"], f["dst_ip"], f["dst_port"])].append(f)
        for (src, dst, port), sfl in sessions.items():
            if len(sfl) >= 3:
                sizes = [f["bytes_sent"] for f in sfl]
                durs = [f["duration"] for f in sfl]
                sv = self._var(sizes)
                dv = self._var(durs)
                if sv < 5000 and dv < 5 and max(durs) > 20:
                    self._alert("C2 Beaconing Pattern Detected", "critical", src,
                        MITRE["c2_beacon"],
                        {"dst_ip": dst, "port": port,
                         "connections": len(sfl), "size_variance": round(sv, 2)})

    def _dns_tunneling(self, flows):
        for f in flows:
            if f["dst_port"] == 53 and f["bytes_sent"] > 4096:
                self._alert("DNS Tunneling Suspected", "high", f["src_ip"],
                    MITRE["dns_tunnel"],
                    {"bytes_sent": f["bytes_sent"], "dst_ip": f["dst_ip"]})

    def _lateral_smb(self, flows):
        for f in flows:
            if f["dst_port"] == 445 and f["bytes_sent"] > 500000:
                self._alert("Suspicious SMB Lateral Movement", "high", f["src_ip"],
                    MITRE["lateral_smb"],
                    {"bytes_sent": f["bytes_sent"], "dst_ip": f["dst_ip"], "duration": f["duration"]})

    def _high_risk_ports(self, flows):
        HR = {4444, 1337, 31337, 9001, 6667}
        for f in flows:
            if f["dst_port"] in HR:
                self._alert(
                    "Connection to High-Risk Port " + str(f["dst_port"]),
                    "critical", f["src_ip"], MITRE["high_risk_port"],
                    {"dst_ip": f["dst_ip"], "port": f["dst_port"], "bytes_sent": f["bytes_sent"]})

    def _zscore_volume(self, flows):
        for f in flows:
            p = self.profiles.get(f["src_ip"])
            if not p or p["bytes_sent_std"] == 0:
                continue
            z = (f["bytes_sent"] - p["bytes_sent_mean"]) / p["bytes_sent_std"]
            if abs(z) >= Z_THRESH:
                self._alert("Statistical Volume Anomaly (Z-Score)", "medium", f["src_ip"],
                    MITRE["vol_anomaly"],
                    {"z_score": round(z, 2), "bytes_sent": f["bytes_sent"],
                     "baseline_mean": round(p["bytes_sent_mean"], 0),
                     "baseline_std": round(p["bytes_sent_std"], 0)})

    def _var(self, v):
        if len(v) < 2:
            return float("inf")
        m = sum(v) / len(v)
        return sum((x - m) ** 2 for x in v) / len(v)
