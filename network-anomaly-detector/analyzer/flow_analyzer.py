"""
Flow Analyzer - Enriches flows with port risk, volume class, protocol label.
"""
import logging
logger = logging.getLogger(__name__)

HIGH_RISK_PORTS = {4444:"Metasploit default",1337:"Common backdoor",31337:"Elite backdoor",9001:"Tor relay",6667:"IRC C2"}
PROTO_LABELS = {"TCP":"connection-oriented","UDP":"connectionless","ICMP":"diagnostic"}

class FlowAnalyzer:
    def enrich(self, flows):
        enriched = []
        for f in flows:
            f["port_risk"] = self._port_risk(f["dst_port"])
            f["volume_class"] = "LARGE" if f["bytes_sent"]>100000 else "MEDIUM" if f["bytes_sent"]>10000 else "SMALL"
            f["proto_label"] = PROTO_LABELS.get(f.get("protocol","TCP"), "unknown")
            enriched.append(f)
        return enriched

    def _port_risk(self, port):
        if port in HIGH_RISK_PORTS: return f"HIGH — {HIGH_RISK_PORTS[port]}"
        if port in {22,23,3389,5900}: return "MEDIUM — sensitive remote access"
        return "LOW" if port < 1024 else "NOMINAL"
