from providers.mock_provider import MockProvider
from core.risk_engine import RiskEngine
from core.cache import Cache
from core.rate_limiter import RateLimiter
from utils.validators import classify_input
import logging

logger = logging.getLogger(__name__)

class ThreatIntelEnricher:
    def __init__(self):
        self.mock = MockProvider()
        self.risk_engine = RiskEngine()
        self.cache = Cache(ttl_seconds=300)
        self.rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

    def analyze(self, indicator):
        indicator = indicator.strip()
        indicator_type = classify_input(indicator)

        cached = self.cache.get(indicator)
        if cached:
            cached["cached"] = True
            return cached

        if not self.rate_limiter.allow():
            return {"error": "Rate limit exceeded. Please wait before submitting more indicators."}

        if indicator_type == "ip":
            raw_data = self.mock.lookup_ip(indicator)
        elif indicator_type == "domain":
            raw_data = self.mock.lookup_domain(indicator)
        else:
            raw_data = self.mock.lookup_hash(indicator)

        risk_score = self.risk_engine.calculate(raw_data)
        result = {
            "indicator": indicator,
            "type": indicator_type,
            "reputation": raw_data["reputation"],
            "country": raw_data["geo"],
            "detected_by": raw_data["sources"],
            "categories": raw_data.get("categories", []),
            "risk_score": risk_score,
            "cached": False
        }
        self.cache.set(indicator, result)
        return result
