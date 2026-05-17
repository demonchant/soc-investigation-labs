import os
DB_NAME = os.environ.get("SIEM_DB", "siem.db")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
