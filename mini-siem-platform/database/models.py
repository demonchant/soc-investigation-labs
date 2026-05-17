from database.db import get_connection
import logging
logger = logging.getLogger(__name__)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user TEXT,
        host TEXT,
        process TEXT,
        raw_log TEXT
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        description TEXT,
        mitre_technique TEXT,
        evidence TEXT,
        timestamp TEXT NOT NULL
    )""")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")

    conn.commit()
    conn.close()
    logger.info("Database initialized.")
