"""
Normalizer — Maps raw CloudTrail event fields to a flat, consistent schema.
"""
import logging
logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["event_name", "event_time"]


def normalize(log):
    for field in REQUIRED_FIELDS:
        if field not in log:
            logger.warning(f"Skipping log missing required field: {field}")
            return None
    return {
        "event_time": log.get("event_time"),
        "event_name": log.get("event_name"),
        "user": log.get("user", "unknown"),
        "user_type": log.get("user_type", "IAMUser"),
        "source_ip": log.get("source_ip", "0.0.0.0"),
        "region": log.get("region", "us-east-1"),
        "status": log.get("status", "success"),
        "user_agent": log.get("user_agent", ""),
        "target_resource": log.get("target_resource", ""),
        "mfa_used": log.get("mfa_used", False),
        "raw": log
    }
