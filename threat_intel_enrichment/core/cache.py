import time, logging
logger = logging.getLogger(__name__)

class Cache:
    def __init__(self, ttl_seconds=300):
        self.store = {}
        self.ttl = ttl_seconds

    def get(self, key):
        if key in self.store:
            data, ts = self.store[key]
            if time.time() - ts < self.ttl:
                return data
            del self.store[key]
        return None

    def set(self, key, value):
        self.store[key] = (value, time.time())

    def stats(self):
        return {"cached_entries": len(self.store), "ttl_seconds": self.ttl}
