"""
Log Parser — Ingests and normalizes raw JSON logs for the detection pipeline.
Supports extensible field normalization and basic validation.
"""
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["timestamp", "event_type", "source_ip"]


class LogParser:
    def parse(self, file_path):
        try:
            with open(file_path, "r") as f:
                raw_logs = json.load(f)
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return []

        normalized_logs = []
        skipped = 0

        for i, log in enumerate(raw_logs):
            if not self._validate(log, i):
                skipped += 1
                continue
            normalized = {
                "timestamp": log.get("timestamp", "unknown"),
                "host": log.get("host", "unknown"),
                "user": log.get("user", "unknown"),
                "event_type": log.get("event_type"),
                "source_ip": log.get("source_ip"),
                "process": log.get("process", "unknown"),
                "action": log.get("action", "unknown"),
                "raw": log
            }
            normalized_logs.append(normalized)

        if skipped:
            logger.warning(f"Skipped {skipped} malformed log entries.")

        return normalized_logs

    def _validate(self, log, index):
        for field in REQUIRED_FIELDS:
            if field not in log or log[field] is None:
                logger.warning(f"Log entry #{index} missing required field: '{field}'. Skipping.")
                return False
        return True
