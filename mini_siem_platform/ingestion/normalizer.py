import logging
logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["timestamp", "source_ip", "event_type"]

def normalize(log):
    for field in REQUIRED_FIELDS:
        if field not in log:
            logger.warning(f"Log missing required field: {field}. Skipping.")
            return None
    return {
        "timestamp": log.get("timestamp"),
        "source_ip": log.get("source_ip"),
        "event_type": log.get("event_type"),
        "user": log.get("user", "unknown"),
        "host": log.get("host", "unknown"),
        "process": log.get("process", "unknown"),
        "raw_log": str(log)
    }
