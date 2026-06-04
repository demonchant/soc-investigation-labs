"""
IDS Signature Engine - Matches network packets against detection signatures.
Uses regex-based pattern matching similar to Snort/Suricata rule engines.
All signatures detect real attack patterns used in defensive security research.
"""
import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)


class IDSEngine:
    def __init__(self, signatures):
        self.signatures = signatures
        self.alerts = []
        self._compiled = {}
        for sig in signatures:
            try:
                self._compiled[sig["id"]] = re.compile(sig["pattern"], re.I | re.S)
            except re.error as e:
                logger.warning(f"Bad pattern in {sig['id']}: {e}")

    def run(self, packets):
        for pkt in packets:
            for sig in self.signatures:
                self._check(pkt, sig)
        logger.info(f"IDS scan complete. {len(self.alerts)} alert(s).")
        return self.alerts

    def _check(self, pkt, sig):
        # Port filter
        sig_port = sig.get("port")
        if sig_port and pkt.get("dst_port") != sig_port and pkt.get("src_port") != sig_port:
            return
        # Protocol filter
        if sig.get("protocol") and sig["protocol"].upper() != pkt.get("protocol","").upper():
            return
        # Pattern match against payload
        payload = pkt.get("payload","")
        pat = self._compiled.get(sig["id"])
        if pat and pat.search(payload):
            self.alerts.append({
                "packet_id":    pkt["id"],
                "sig_id":       sig["id"],
                "sig_name":     sig["name"],
                "severity":     sig["severity"],
                "category":     sig["category"],
                "mitre":        sig["mitre"],
                "src_ip":       pkt["src_ip"],
                "dst_ip":       pkt["dst_ip"],
                "dst_port":     pkt.get("dst_port"),
                "protocol":     pkt.get("protocol"),
                "timestamp":    pkt["timestamp"],
                "description":  sig["description"],
                "payload_snip": payload[:100],
            })
