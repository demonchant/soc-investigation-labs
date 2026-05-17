from flask import Flask, jsonify, request
from database.db import get_connection
import json

app = Flask(__name__)


def row_to_dict(rows):
    return [dict(r) for r in rows]


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "mini-siem-platform"})


@app.route("/alerts")
def alerts():
    severity = request.args.get("severity")
    conn = get_connection()
    cursor = conn.cursor()
    if severity:
        cursor.execute("SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC", (severity,))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    data = row_to_dict(cursor.fetchall())
    conn.close()
    return jsonify({"count": len(data), "alerts": data})


@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id=?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Alert not found"}), 404
    result = dict(row)
    if result.get("evidence"):
        try:
            result["evidence"] = json.loads(result["evidence"])
        except Exception:
            pass
    return jsonify(result)


@app.route("/logs")
def logs():
    event_type = request.args.get("event_type")
    limit = int(request.args.get("limit", 100))
    conn = get_connection()
    cursor = conn.cursor()
    if event_type:
        cursor.execute("SELECT * FROM logs WHERE event_type=? ORDER BY timestamp DESC LIMIT ?", (event_type, limit))
    else:
        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    data = row_to_dict(cursor.fetchall())
    conn.close()
    return jsonify({"count": len(data), "logs": data})


@app.route("/stats")
def stats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    by_sev = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.execute("SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name ORDER BY COUNT(*) DESC")
    by_rule = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return jsonify({
        "total_logs_ingested": total_logs,
        "total_alerts": total_alerts,
        "alerts_by_severity": by_sev,
        "alerts_by_rule": by_rule
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
