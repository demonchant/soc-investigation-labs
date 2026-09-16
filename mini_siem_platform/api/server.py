from flask import Flask, jsonify, request
from database.db import get_connection
from app.config import FLASK_DEBUG, FLASK_PORT, MAX_API_LIMIT, SIEM_API_KEY
from functools import wraps
import hmac
import json

app = Flask(__name__)


def require_api_key(view):
    """Enforce API authentication when SIEM_API_KEY is configured."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if SIEM_API_KEY:
            supplied = request.headers.get("X-API-Key", "")
            bearer = request.headers.get("Authorization", "")
            if bearer.lower().startswith("bearer "):
                supplied = bearer[7:]
            if not hmac.compare_digest(supplied, SIEM_API_KEY):
                return jsonify({"error": "Unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def row_to_dict(rows):
    return [dict(r) for r in rows]


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "mini-siem-platform"})


@app.route("/alerts")
@require_api_key
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
@require_api_key
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
@require_api_key
def logs():
    event_type = request.args.get("event_type")
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    limit = max(1, min(limit, MAX_API_LIMIT))
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
@require_api_key
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


def _configure_console():
    """Keep Unicode reports readable on Windows and redirected terminals."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    _configure_console()
    app.run(debug=FLASK_DEBUG, port=FLASK_PORT)
