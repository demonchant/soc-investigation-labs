import time, logging
logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = []

    def allow(self):
        now = time.time()
        self.requests = [t for t in self.requests if now - t < self.window]
        if len(self.requests) >= self.max_requests:
            return False
        self.requests.append(now)
        return True

    def remaining(self):
        now = time.time()
        return max(0, self.max_requests - len([t for t in self.requests if now - t < self.window]))
