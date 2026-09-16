"""Email Parser — Loads and validates email records for analysis."""
import json, logging
logger = logging.getLogger(__name__)

class EmailParser:
    def load(self, file_path):
        with open(file_path) as f:
            emails = json.load(f)
        logger.info(f"Loaded {len(emails)} email(s).")
        return emails
