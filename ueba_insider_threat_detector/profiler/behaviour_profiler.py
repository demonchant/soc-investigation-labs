"""
Behaviour Profiler - Builds per-user activity baselines.
Tracks normal working hours, typical data volumes, usual hosts,
and common action types to enable anomaly detection.
"""
import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

class BehaviourProfiler:
    def build(self, events):
        profiles = defaultdict(lambda: {
            "hours": [], "data_mb": [], "files": [],
            "hosts": set(), "countries": set(), "actions": []
        })
        for ev in events:
            u = ev["user"]
            profiles[u]["hours"].append(ev.get("hour", 9))
            profiles[u]["data_mb"].append(ev.get("data_mb", 0))
            profiles[u]["files"].append(ev.get("files_accessed", 0))
            profiles[u]["hosts"].add(ev.get("host", ""))
            profiles[u]["countries"].add(ev.get("country", ""))
            profiles[u]["actions"].append(ev.get("action", ""))

        built = {}
        for user, p in profiles.items():
            hours = p["hours"]
            data = p["data_mb"]
            built[user] = {
                "user": user,
                "typical_hours": {"min": min(hours), "max": max(hours)},
                "avg_data_mb": sum(data) / len(data) if data else 0,
                "max_data_mb": max(data) if data else 0,
                "known_hosts": list(p["hosts"]),
                "known_countries": list(p["countries"]),
                "action_count": len(p["actions"]),
            }
        logger.info(f"Profiles built for {len(built)} user(s).")
        return built
