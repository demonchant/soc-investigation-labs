"""Session Aggregator — Groups honeypot events by attacker IP."""
import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

class SessionAggregator:
    def aggregate(self, events):
        sessions = defaultdict(list)
        for ev in events:
            sessions[ev["attacker_ip"]].append(ev)
        logger.info("Aggregated " + str(len(events)) + " events into " + str(len(sessions)) + " session(s).")
        return dict(sessions)
