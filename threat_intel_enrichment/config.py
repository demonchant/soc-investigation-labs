"""
Config — Central configuration for the enrichment tool.
Override values via environment variables.
"""
import os

CACHE_TTL = int(os.environ.get("CACHE_TTL", 300))
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", 10))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", 60))
VT_API_KEY = os.environ.get("VT_API_KEY", "")
