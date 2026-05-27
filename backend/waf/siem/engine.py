import json
import time
from datetime import UTC, datetime
from typing import Any

from waf.db import execute_db, query_db

_SIEM_RULES: list[dict[str, Any]] = []
_SIEM_INITIALIZED = False


SIEM_RULE_DEFINITIONS = [
    {
        "rule_id": "siem-multi-fail-001",
        "rule_name": "Multiple Failed Logins",
        "severity": "high",
        "description": "Detects repeated authentication failures from a single source",
        "query": "SELECT COUNT(*) as cnt FROM hids_alerts WHERE log_type = 'auth_failure' AND timestamp > datetime('now', '-5 minutes')",
        "threshold": 5,
        "cooldown": 300,
    },
    {
        "rule_id": "siem-port-scan-001",
        "rule_name": "Port Scan Detection",
        "severity": "medium",
        "description": "Detects rapid connections to multiple ports from a single IP",
        "query": "SELECT COUNT(DISTINCT target_uri) as cnt FROM security_events WHERE timestamp > datetime('now', '-1 minute')",
        "threshold": 20,
        "cooldown": 120,
    },
    {
        "rule_id": "siem-fim-critical-001",
        "rule_name": "Critical File Change",
        "severity": "critical",
        "description": "Detects modifications to critical system files",
        "query": "SELECT COUNT(*) as cnt FROM fim_events WHERE change_type IN ('modified', 'deleted') AND timestamp > datetime('now', '-10 minutes')",
        "threshold": 1,
        "cooldown": 600,
    },
    {
        "rule_id": "siem-xss-wave-001",
        "rule_name": "XSS Attack Wave",
        "severity": "high",
        "description": "Detects a wave of XSS attacks targeting the application",
        "query": "SELECT COUNT(*) as cnt FROM security_events WHERE threat_category = 'XSS' AND timestamp > datetime('now', '-5 minutes')",
        "threshold": 10,
        "cooldown": 300,
    },
    {
        "rule_id": "siem-sqli-wave-001",
        "rule_name": "SQLi Attack Wave",
        "severity": "critical",
        "description": "Detects a wave of SQL injection attacks",
        "query": "SELECT COUNT(*) as cnt FROM security_events WHERE threat_category = 'SQLi' AND timestamp > datetime('now', '-5 minutes')",
        "threshold": 5,
        "cooldown": 300,
    },
    {
        "rule_id": "siem-anomaly-traffic-001",
        "rule_name": "Anomalous Traffic Spike",
        "severity": "medium",
        "description": "Detects unusual spikes in overall traffic volume",
        "query": "SELECT COUNT(*) as cnt FROM security_events WHERE timestamp > datetime('now', '-1 minute')",
        "threshold": 50,
        "cooldown": 60,
    },
    {
        "rule_id": "siem-vuln-exploit-001",
        "rule_name": "Vulnerability Exploit Attempt",
        "severity": "critical",
        "description": "Detects attempted exploitation of known vulnerabilities",
        "query": "SELECT COUNT(*) as cnt FROM security_events WHERE threat_category IN ('RFI', 'LFI', 'RCE') AND timestamp > datetime('now', '-10 minutes')",
        "threshold": 3,
        "cooldown": 600,
    },
]

_last_fired: dict[str, float] = {}


def init_siem():
    global _SIEM_INITIALIZED
    if _SIEM_INITIALIZED:
        return
    _SIEM_RULES.clear()
    _SIEM_RULES.extend(SIEM_RULE_DEFINITIONS)
    _SIEM_INITIALIZED = True
    print(f"[SIEM] Engine initialized with {len(_SIEM_RULES)} detection rules")


def ingest_log(source: str, log_type: str, content: str, severity: str = "info") -> int | None:
    result = execute_db(
        "INSERT INTO hids_alerts (log_source, log_type, log_content, severity) VALUES (?, ?, ?, ?)",
        (source, log_type, content[:2000], severity),
    )
    if result:
        row = query_db("SELECT last_insert_rowid() as rid", one=True)
        return row["rid"] if row else None
    return None


def correlate_events(window_minutes: int = 5) -> list[dict[str, Any]]:
    correlations = []
    recent_events = query_db(
        "SELECT threat_category, COUNT(*) as cnt FROM security_events "
        "WHERE timestamp > datetime('now', ? || ' minutes') "
        "GROUP BY threat_category ORDER BY cnt DESC",
        (str(-window_minutes),),
    )
    if recent_events:
        for event in recent_events:
            correlations.append({
                "type": event["threat_category"],
                "count": event["cnt"],
                "window_minutes": window_minutes,
            })
    return correlations


def run_detection_rules() -> list[dict[str, Any]]:
    now = time.time()
    triggered: list[dict[str, Any]] = []

    for rule in _SIEM_RULES:
        rule_id = rule["rule_id"]
        if rule_id in _last_fired and (now - _last_fired[rule_id]) < rule["cooldown"]:
            continue

        try:
            result = query_db(rule["query"], one=True)
            if result and result.get("cnt", 0) >= rule["threshold"]:
                alert = {
                    "rule_id": rule_id,
                    "rule_name": rule["rule_name"],
                    "severity": rule["severity"],
                    "source": "siem_correlation",
                    "description": rule["description"],
                    "raw_data": json.dumps({"trigger_count": result["cnt"], "threshold": rule["threshold"]}),
                }
                execute_db(
                    "INSERT INTO siem_alerts (rule_id, rule_name, severity, source, description, raw_data) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (alert["rule_id"], alert["rule_name"], alert["severity"],
                     alert["source"], alert["description"], alert["raw_data"]),
                )
                triggered.append(alert)
                _last_fired[rule_id] = now
                print(f"[SIEM] ALERT: {rule['rule_name']} ({rule['severity']})")
        except Exception as e:
            print(f"[SIEM] Rule check failed for {rule_id}: {e}")

    return triggered


def get_alerts(
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
    unacked_only: bool = False,
) -> list[dict[str, Any]]:
    conditions = []
    params: list[Any] = []
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if unacked_only:
        conditions.append("acked = 0")
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    rows = query_db(
        f"SELECT * FROM siem_alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    )
    return rows or []


def acknowledge_alert(alert_id: int) -> bool:
    return bool(execute_db("UPDATE siem_alerts SET acked = 1 WHERE id = ?", (alert_id,)))


def get_alert_stats() -> dict[str, Any]:
    total = query_db("SELECT COUNT(*) as cnt FROM siem_alerts", one=True)
    unacked = query_db("SELECT COUNT(*) as cnt FROM siem_alerts WHERE acked = 0", one=True)
    by_severity = query_db(
        "SELECT severity, COUNT(*) as cnt FROM siem_alerts GROUP BY severity ORDER BY cnt DESC"
    )
    return {
        "total": total["cnt"] if total else 0,
        "unacknowledged": unacked["cnt"] if unacked else 0,
        "by_severity": {r["severity"]: r["cnt"] for r in by_severity} if by_severity else {},
    }
