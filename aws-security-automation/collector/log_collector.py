"""
Log Collector — Loads CloudTrail-format logs from disk.
In production, replace with boto3 CloudWatch Logs / S3 reader.
"""
import json, logging, os
logger = logging.getLogger(__name__)


class LogCollector:
    def collect(self, file_path):
        if not os.path.exists(file_path):
            logger.error(f"Log file not found: {file_path}")
            return []
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            # Support both wrapped {"Records": [...]} and flat list formats
            if isinstance(data, dict) and "Records" in data:
                logs = data["Records"]
            elif isinstance(data, list):
                logs = data
            else:
                logger.error("Unrecognised log format.")
                return []
            logger.info(f"Collected {len(logs)} CloudTrail event(s).")
            return logs
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return []
