"""
Crypto Exchange Security Detection Engine
Detects: account takeover chains, wash trading, API abuse, brute force,
structuring (smurfing), impossible travel, and KYC fraud.
Mapped to MITRE ATT&CK and financial regulations (FINRA, FinCEN/BSA, FATF).
"""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY", "BY"}
CTR_THRESHOLD_USD = 10000  # FinCEN Currency Transaction Report threshold

MITRE = {
    "impossible_travel": "T1078.004 - Compromised Cloud Account (Impossible Travel)",
    "account_takeover":  "T1078 + T1098.001 - Account Takeover + New API Credentials",
    "api_abuse":         "T1498 - Network/API Flood / Order Stuffing",
    "brute_force":       "T1110 - Brute Force",
    "wash_trading":      "FIN-001 - Wash Trading / Market Manipulation",
    "structuring":       "FIN-002 - Structuring / Smurfing (FinCEN/BSA)",
    "kyc_fraud":         "FIN-003 - KYC Bypass / Identity Fraud (FATF R.10)",
}


class ExchangeSecurityEngine:
    def __init__(self):
        self.alerts = []

    def run(self, events):
        self._impossible_travel(events)
        self._ato_withdrawal_chain(events)
        self._api_abuse(events)
        self._brute_force(events)
        self._wash_trading(events)
        self._structuring(events)
        self._kyc_fraud(events)
        logger.info("Exchange detection complete. " + str(len(self.alerts)) + " alert(s).")
        return self.alerts

    def _alert(self, title, severity, user_id, technique, evidence, regulation=None):
        a = {"title": title, "severity": severity, "user_id": user_id,
             "mitre_technique": technique, "evidence": evidence}
        if regulation:
            a["regulation"] = regulation
        self.alerts.append(a)

    def _impossible_travel(self, events):
        user_logins = defaultdict(list)
        for ev in events:
            if ev["event_type"] == "login" and ev.get("status") == "success":
                user_logins[ev["user_id"]].append(ev)
        for uid, logins in user_logins.items():
            countries = [l["country"] for l in logins]
            ips = [l["ip"] for l in logins]
            fps = [l.get("device_fingerprint","") for l in logins]
            if len(set(countries)) > 1 or len(set(ips)) > 1:
                self._alert(
                    "Impossible Travel / Multi-Location Login Detected",
                    "critical", uid, MITRE["impossible_travel"],
                    {"countries": list(set(countries)), "ips": list(set(ips)),
                     "new_device": len(set(fps)) > 1,
                     "mfa_on_new_login": logins[-1].get("mfa_used", "unknown")})

    def _ato_withdrawal_chain(self, events):
        risky_logins = set()
        api_withdraw_users = set()
        for ev in events:
            uid = ev["user_id"]
            if ev["event_type"] == "login" and ev.get("country") in HIGH_RISK_COUNTRIES:
                risky_logins.add(uid)
            if ev["event_type"] == "api_key_created" and "withdraw" in ev.get("permissions", []):
                if uid in risky_logins:
                    api_withdraw_users.add(uid)
        for ev in events:
            uid = ev["user_id"]
            if ev["event_type"] == "withdrawal" and uid in api_withdraw_users:
                self._alert(
                    "Account Takeover Chain: Risky Login + New Withdraw API Key + Withdrawal",
                    "critical", uid, MITRE["account_takeover"],
                    {"amount_usd": ev.get("amount_usd"), "asset": ev.get("asset"),
                     "destination": ev.get("destination_address"),
                     "src_country": ev.get("country")})

    def _api_abuse(self, events):
        for ev in events:
            if ev["event_type"] == "api_request" and ev.get("requests_per_min", 0) > 300:
                self._alert(
                    "API Rate Abuse — Order Flooding or Market Data Scraping",
                    "high", ev["user_id"], MITRE["api_abuse"],
                    {"requests_per_min": ev["requests_per_min"],
                     "endpoint": ev.get("endpoint"),
                     "src_ip": ev["ip"], "country": ev["country"]})

    def _brute_force(self, events):
        fails = defaultdict(list)
        for ev in events:
            if ev["event_type"] == "login" and ev.get("status") == "failed":
                fails[ev["user_id"]].append(ev)
        for uid, attempts in fails.items():
            if len(attempts) >= 5:
                self._alert(
                    "Account Brute Force Attack Detected",
                    "high", uid, MITRE["brute_force"],
                    {"attempts": len(attempts), "src_ip": attempts[0]["ip"],
                     "mfa_enforced": attempts[0].get("mfa_used", False)})

    def _wash_trading(self, events):
        trades = [e for e in events if e["event_type"] == "trade"]
        by_pair = defaultdict(list)
        for t in trades:
            by_pair[t["pair"]].append(t)
        for pair, pt in by_pair.items():
            buys = [t for t in pt if t["side"] == "buy"]
            sells = [t for t in pt if t["side"] == "sell"]
            buy_users = {t["user_id"] for t in buys}
            sell_users = {t["user_id"] for t in sells}
            if len(buy_users) >= 2 and len(sell_users) >= 2 and buy_users != sell_users:
                buy_amts = [t["amount_usd"] for t in buys]
                sell_amts = [t["amount_usd"] for t in sells]
                bm = sum(buy_amts) / len(buy_amts)
                sm = sum(sell_amts) / len(sell_amts)
                if abs(bm - sm) / max(bm, sm) < 0.05:
                    self._alert(
                        "Wash Trading Pattern — Coordinated Buy/Sell Volume Manipulation",
                        "critical",
                        "Group: " + str(list(buy_users)) + " <-> " + str(list(sell_users)),
                        MITRE["wash_trading"],
                        {"pair": pair, "buy_users": list(buy_users), "sell_users": list(sell_users),
                         "avg_buy_usd": round(bm, 2), "avg_sell_usd": round(sm, 2),
                         "total_transactions": len(pt)},
                        regulation="FINRA Rule 6140 / Market Manipulation")

    def _structuring(self, events):
        wds = defaultdict(list)
        for ev in events:
            if ev["event_type"] == "withdrawal":
                wds[ev["user_id"]].append(ev)
        for uid, user_wds in wds.items():
            if len(user_wds) >= 3:
                total = sum(w["amount_usd"] for w in user_wds)
                all_below = all(w["amount_usd"] < CTR_THRESHOLD_USD for w in user_wds)
                unique_addrs = len({w["destination_address"] for w in user_wds})
                if all_below and total > CTR_THRESHOLD_USD and unique_addrs >= 2:
                    self._alert(
                        "Currency Structuring / Smurfing Detected",
                        "critical", uid, MITRE["structuring"],
                        {"total_usd": total, "transactions": len(user_wds),
                         "unique_addresses": unique_addrs,
                         "individual_amounts": [w["amount_usd"] for w in user_wds]},
                        regulation="FinCEN/BSA 31 CFR 1010.314 — Currency Structuring")

    def _kyc_fraud(self, events):
        for ev in events:
            if ev["event_type"] == "kyc_bypass_attempt":
                self._alert(
                    "KYC Bypass / Identity Fraud Attempt",
                    "critical", ev["user_id"], MITRE["kyc_fraud"],
                    {"method": ev.get("method"), "ip": ev["ip"], "country": ev["country"]},
                    regulation="FATF Recommendation 10 — Customer Due Diligence")
