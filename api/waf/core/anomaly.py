import math
from collections import Counter
from datetime import datetime

_KNOWN_UA_SUBSTRINGS = [
    "chrome",
    "firefox",
    "safari",
    "edge",
    "opera",
    "msie",
    "trident",
    "curl/",
    "wget/",
    "python-requests",
    "axios",
    "undici",
    "go-http-client",
    "kalki-agent",
    "kalki-waf",
    "datadog",
    "prometheus",
]

_ENTROPY_THRESHOLD = 5.5

ANOMALY_THRESHOLD = 25.0


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def score_header_entropy(headers: dict) -> float:
    score = 0.0
    for h in ("user-agent", "referer", "x-forwarded-for", "cookie", "authorization"):
        val = headers.get(h, "")
        if not val or val == "Unknown":
            continue
        ent = shannon_entropy(val)
        if ent > _ENTROPY_THRESHOLD:
            score += (ent - _ENTROPY_THRESHOLD) * 2
    return min(score, 20.0)


def score_ua_rarity(user_agent: str) -> float:
    if not user_agent or user_agent == "Unknown":
        return 15.0
    ua_lower = user_agent.lower()
    for known in _KNOWN_UA_SUBSTRINGS:
        if known in ua_lower:
            return 0.0
    if len(ua_lower) < 10:
        return 12.0
    if shannon_entropy(ua_lower) > 5.0:
        return 8.0
    return 5.0


def score_time_of_day() -> float:
    hour = datetime.now().hour
    if 0 <= hour < 6:
        return 10.0
    if 6 <= hour < 7 or 23 <= hour < 24:
        return 5.0
    if 22 <= hour < 23:
        return 2.0
    return 0.0


def compute_anomaly_score(headers: dict, user_agent: str = "") -> float:
    ua = user_agent or headers.get("user-agent", "Unknown")
    score = score_header_entropy(headers) + score_ua_rarity(ua) + score_time_of_day()
    return round(min(score, 50.0), 1)


def check_anomaly(source_ip: str, headers: dict, user_agent: str = "") -> float:
    """Compute anomaly score and create SIEM alert if exceeding threshold.

    Returns the anomaly score. Caller should check if > 0 for logging.
    """
    score = compute_anomaly_score(headers, user_agent)
    if score >= ANOMALY_THRESHOLD:
        import json

        from waf.db import execute_db

        execute_db(
            "INSERT INTO siem_alerts (rule_id, rule_name, severity, source, description, raw_data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "siem-anomaly-001",
                "Request Anomaly Score",
                "low",
                source_ip,
                f"Anomaly score {score} exceeded threshold {ANOMALY_THRESHOLD}",
                json.dumps({"score": score, "threshold": ANOMALY_THRESHOLD}),
            ),
        )
    return score
