import json
import os
import re
from datetime import UTC, datetime
from typing import Any

from waf.db import execute_db, query_db

_AUTH_LOG_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"Failed password for .* from (\S+)", "auth_failure", "high", "SSH authentication failure"),
    (r"Accepted password for .* from (\S+)", "auth_success", "info", "SSH authentication success"),
    (r"Invalid user .* from (\S+)", "auth_failure", "high", "SSH invalid user attempt"),
    (r"Connection closed by authenticating user (\S+)", "auth_failure", "medium", "SSH connection closed during auth"),
    (r"sudo:.*COMMAND=(.*)", "cmd_exec", "medium", "Sudo command execution"),
    (r"REJECT.*SRC=(\S+).*DPT=(\d+)", "fw_reject", "medium", "Firewall packet rejection"),
    (r"DROPT.*SRC=(\S+).*DPT=(\d+)", "fw_drop", "medium", "Firewall packet drop"),
    (r"CRON\[\d+\]:.*\((\S+)\) CMD \((.*)\)", "cron_job", "info", "Cron job execution"),
]

_BRUTEFORCE_THRESHOLD = 5
_BRUTEFORCE_WINDOW = 300

_recent_failures: dict[str, list[float]] = {}


def parse_log_line(line: str, source: str = "system") -> dict[str, Any] | None:
    for pattern, log_type, severity, desc in _AUTH_LOG_PATTERNS:
        match = re.search(pattern, line)
        if match:
            return {
                "log_source": source,
                "log_type": log_type,
                "log_content": line,
                "severity": severity,
                "matched_rule": desc,
            }
    return None


def ingest_log_line(line: str, source: str = "system") -> dict[str, Any] | None:
    parsed = parse_log_line(line, source)
    if not parsed:
        return None
    execute_db(
        "INSERT INTO hids_alerts (log_source, log_type, log_content, matched_rule, severity) VALUES (?, ?, ?, ?, ?)",
        (parsed["log_source"], parsed["log_type"], parsed["log_content"], parsed["matched_rule"], parsed["severity"]),
    )
    return parsed


def detect_bruteforce(source_ip: str = "unknown") -> dict[str, Any] | None:
    import time
    now = time.time()
    if source_ip not in _recent_failures:
        _recent_failures[source_ip] = []
    _recent_failures[source_ip] = [
        t for t in _recent_failures[source_ip] if now - t < _BRUTEFORCE_WINDOW
    ]
    if len(_recent_failures[source_ip]) >= _BRUTEFORCE_THRESHOLD:
        severity = "critical" if len(_recent_failures[source_ip]) >= 20 else "high"
        alert = {
            "source_ip": source_ip,
            "log_source": "hids_correlation",
            "log_type": "bruteforce",
            "log_content": f"Brute force detected from {source_ip}: {len(_recent_failures[source_ip])} failures in {_BRUTEFORCE_WINDOW}s",
            "severity": severity,
            "matched_rule": f"brute_force_detection_{severity}",
        }
        execute_db(
            "INSERT INTO hids_alerts (log_source, log_type, log_content, matched_rule, severity) VALUES (?, ?, ?, ?, ?)",
            (alert["log_source"], alert["log_type"], alert["log_content"], alert["matched_rule"], alert["severity"]),
        )
        return alert
    return None


def add_failure(source_ip: str):
    import time
    if source_ip not in _recent_failures:
        _recent_failures[source_ip] = []
    _recent_failures[source_ip].append(time.time())


def get_hids_alerts(
    severity: str | None = None,
    log_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conditions = []
    params: list[Any] = []
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if log_type:
        conditions.append("log_type = ?")
        params.append(log_type)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    rows = query_db(
        f"SELECT * FROM hids_alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    )
    return rows or []


def get_hids_stats() -> dict[str, Any]:
    total = query_db("SELECT COUNT(*) as cnt FROM hids_alerts", one=True)
    by_severity = query_db(
        "SELECT severity, COUNT(*) as cnt FROM hids_alerts GROUP BY severity ORDER BY cnt DESC"
    )
    by_type = query_db(
        "SELECT log_type, COUNT(*) as cnt FROM hids_alerts GROUP BY log_type ORDER BY cnt DESC"
    )
    return {
        "total": total["cnt"] if total else 0,
        "by_severity": {r["severity"]: r["cnt"] for r in by_severity} if by_severity else {},
        "by_type": {r["log_type"]: r["cnt"] for r in by_type} if by_type else {},
    }
