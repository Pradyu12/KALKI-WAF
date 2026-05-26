import asyncio

import psutil

from waf import state


async def _metrics_sampler():
    next_ts = asyncio.get_event_loop().time()
    while True:
        try:
            state.LIVE_STATS["cpu_percent"] = psutil.cpu_percent(interval=None)
            state.LIVE_STATS["memory_mb"] = round(psutil.Process().memory_info().rss / 1024 / 1024, 1)
            state.LIVE_STATS["requests_per_second"] = round(state._request_count / 2.0, 2)
            state.LIVE_STATS["active_connections"] = state.LIVE_STATS.get("active_connections", 0)
            state._request_count = 0
        except Exception:
            pass
        next_ts += 2.0
        now = asyncio.get_event_loop().time()
        await asyncio.sleep(max(0, next_ts - now))


def start_metrics_sampler():
    state._metrics_task = asyncio.create_task(_metrics_sampler())
    return state._metrics_task


async def stop_metrics_sampler():
    if state._metrics_task:
        state._metrics_task.cancel()
        state._metrics_task = None


def fetch_telemetry_data():
    from waf.config import RATE_LIMIT_THRESHOLD, UPSTREAM_SERVER_URL
    from waf.db import FIREBASE_ENABLED, query_db

    total_blocked_row = query_db(
        "SELECT COUNT(*) as total FROM security_events WHERE mitigation_action = 'Blocked'", one=True
    )  # noqa: E501
    total_blocked = total_blocked_row["total"] if total_blocked_row else 0

    sqli_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'SQLi'", one=True)
    sqli_count = sqli_count_row["total"] if sqli_count_row else 0

    xss_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'XSS'", one=True)
    xss_count = xss_count_row["total"] if xss_count_row else 0

    anomalous_count_row = query_db(
        "SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'Anomalous'", one=True
    )  # noqa: E501
    anomalous_count = anomalous_count_row["total"] if anomalous_count_row else 0

    incidents = query_db("""
        SELECT incident_id, timestamp, source_ip, threat_category, target_uri, mitigation_action, user_agent, malicious_payload
        FROM security_events
        ORDER BY timestamp DESC LIMIT 30
    """)  # noqa: E501
    if not incidents:
        incidents = []

    for inc in incidents:
        if inc["timestamp"] and not isinstance(inc["timestamp"], str):
            inc["timestamp"] = inc["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        from waf.security.geoip import get_geo_location
        geo = get_geo_location(inc.get("source_ip", ""))
        inc["geo"] = {
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city"),
            "country": geo.get("country"),
        }

    rules = query_db("SELECT * FROM rules")
    if not rules:
        rules = []

    db_type = "FIREBASE" if FIREBASE_ENABLED else "SQLITE"

    from waf.config import FIREWALL_LABEL, FIREWALL_LAT, FIREWALL_LON

    return {
        "metrics": {
            "total_ingress": total_blocked + 1524,
            "total_blocked": total_blocked,
            "sqli_count": sqli_count,
            "xss_count": xss_count,
            "anomalous_count": anomalous_count,
            "active_rules_count": len(state.ACTIVE_RULES_CACHE),
            "posture": state.GLOBAL_POSTURE,
            "upstream_url": UPSTREAM_SERVER_URL,
            "rate_limit": RATE_LIMIT_THRESHOLD,
            "db_type": db_type,
        },
        "firewall": {
            "lat": FIREWALL_LAT,
            "lon": FIREWALL_LON,
            "label": FIREWALL_LABEL,
        },
        "incidents": incidents,
        "rules": rules,
    }
