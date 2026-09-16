from database.db import get_connection
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def create_alert(rule_name, severity, source_ip, description, mitre="", evidence=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (rule_name, severity, source_ip, description, mitre_technique, evidence, timestamp) VALUES (?,?,?,?,?,?,?)",
        (rule_name, severity, source_ip, description, mitre, evidence, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    logger.info(f"Alert created: [{severity.upper()}] {rule_name} — {source_ip}")

def get_all_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
