"""
Baseline Profiler - Builds per-IP statistical behaviour profiles.
Computes mean and population stddev for bytes_sent and duration.
"""
import math, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

class BaselineProfiler:
    def __init__(self):
        self.profiles = {}

    def build(self, flows):
        grouped = defaultdict(list)
        for f in flows:
            grouped[f["src_ip"]].append(f)
        for ip, ip_flows in grouped.items():
            self.profiles[ip] = self._compute(ip, ip_flows)
        logger.info(f"Baseline built for {len(self.profiles)} host(s).")
        return self.profiles

    def _compute(self, ip, flows):
        bs = [f["bytes_sent"] for f in flows]
        dur = [f["duration"] for f in flows]
        return {
            "ip": ip, "sample_count": len(flows),
            "bytes_sent_mean": self._mean(bs), "bytes_sent_std": self._std(bs),
            "duration_mean": self._mean(dur), "duration_std": self._std(dur),
            "unique_dst_ips": len({f["dst_ip"] for f in flows}),
            "unique_dst_ports": len({f["dst_port"] for f in flows}),
        }

    def _mean(self, v): return sum(v)/len(v) if v else 0
    def _std(self, v):
        if len(v) < 2: return 0
        m = self._mean(v)
        return math.sqrt(sum((x-m)**2 for x in v)/len(v))

    def get(self, ip): return self.profiles.get(ip)
