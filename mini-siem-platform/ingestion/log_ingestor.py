import json, logging
from ingestion.normalizer import normalize
from database.db import get_connection

logger = logging.getLogger(__name__)

class LogIngestor:
    def ingest(self, file_path):
        try:
            with open(file_path, "r") as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load logs: {e}")
            return 0

        conn = get_connection()
        cursor = conn.cursor()
        inserted = 0
        skipped = 0

        for log in logs:
            n = normalize(log)
            if not n:
                skipped += 1
                continue
            cursor.execute(
                "INSERT INTO logs (timestamp, source_ip, event_type, user, host, process, raw_log) VALUES (?,?,?,?,?,?,?)",
                (n["timestamp"], n["source_ip"], n["event_type"], n["user"], n["host"], n["process"], n["raw_log"])
            )
            inserted += 1

        conn.commit()
        conn.close()
        logger.info(f"Ingested {inserted} logs. Skipped {skipped}.")
        return inserted
