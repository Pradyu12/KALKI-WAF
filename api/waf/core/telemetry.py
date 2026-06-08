import asyncio
from datetime import datetime, timedelta

try:
    from datetime import UTC
except ImportError:
    UTC = UTC

import psutil

from waf import state

_telemetry_lock = asyncio.Lock()


async def _metrics_sampler():
    next_ts = asyncio.get_event_loop().time()
    while True:
        try:
            state.LIVE_STATS["cpu_percent"] = psutil.cpu_percent(interval=None)
            state.LIVE_STATS["memory_mb"] = round(psutil.Process().memory_info().rss / 1024 / 1024, 1)
            async with _telemetry_lock:
                state.LIVE_STATS["requests_per_second"] = round(state._request_count / 2.0, 2)
                state._request_count = 0
            state.LIVE_STATS["active_connections"] = state.LIVE_STATS.get("active_connections", 0)
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
    )
    total_blocked = total_blocked_row["total"] if total_blocked_row else 0

    sqli_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'SQLi'", one=True)
    sqli_count = sqli_count_row["total"] if sqli_count_row else 0

    xss_count_row = query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'XSS'", one=True)
    xss_count = xss_count_row["total"] if xss_count_row else 0

    anomalous_count_row = query_db(
        "SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'Anomalous'", one=True
    )
    anomalous_count = anomalous_count_row["total"] if anomalous_count_row else 0

    # ── Breakdown by threat category (for doughnut chart) ──────────────
    breakdown_rows = (
        query_db("SELECT threat_category, COUNT(*) as cnt FROM security_events GROUP BY threat_category") or []
    )
    breakdown: dict[str, int] = {}
    for row in breakdown_rows:
        cat = row.get("threat_category") or "Other"
        breakdown[cat] = row.get("cnt", 0)

    # ── 24-hour timeline (hourly buckets) ───────────────────────────────
    now_utc = datetime.now(UTC)
    timeline: list[int] = []
    for h in range(23, -1, -1):
        hour_start = (now_utc - timedelta(hours=h + 1)).strftime("%Y-%m-%d %H:%M:%S")
        hour_end = (now_utc - timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S")
        row = query_db(
            "SELECT COUNT(*) as cnt FROM security_events WHERE timestamp >= ? AND timestamp < ?",
            (hour_start, hour_end),
            one=True,
        )
        timeline.append(row["cnt"] if row else 0)

    # ── Recent incidents with live geo ──────────────────────────────────
    incidents = (
        query_db("""
        SELECT incident_id, timestamp, source_ip, threat_category, target_uri, mitigation_action, user_agent, malicious_payload
        FROM security_events
        ORDER BY timestamp DESC LIMIT 30
    """)
        or []
    )

    for inc in incidents:
        # Normalise timestamp to plain string (no trailing Z)
        ts = inc.get("timestamp")
        if ts and not isinstance(ts, str):
            inc["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(ts, str):
            inc["timestamp"] = ts.rstrip("Z")

        from waf.security.geoip import get_geo_location

        geo = get_geo_location(inc.get("source_ip", ""))
        inc["geo"] = {
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city"),
            "country": geo.get("country"),
        }

    rules = query_db("SELECT * FROM rules") or []

    db_type = "FIREBASE" if FIREBASE_ENABLED else "SQLITE"

    from waf.config import FIREWALL_LABEL, FIREWALL_LAT, FIREWALL_LON

    return {
        "metrics": {
            "total_ingress": total_blocked + sqli_count + xss_count + anomalous_count,
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
        "breakdown": breakdown,
        "timeline": timeline,
        "incidents": incidents,
        "rules": rules,
    }
