import os
DB_NAME = os.environ.get("SIEM_DB", "siem.db")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
SIEM_API_KEY = os.environ.get("SIEM_API_KEY", "")
MAX_API_LIMIT = int(os.environ.get("MAX_API_LIMIT", 500))
