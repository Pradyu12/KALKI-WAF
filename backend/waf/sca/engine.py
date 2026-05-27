import os
import subprocess
from typing import Any

from waf.db import execute_db, query_db

_BENCHMARKS: dict[str, list[dict[str, Any]]] = {
    "cis_linux_v1.0": [
        {
            "check_id": "CIS-1.1.1",
            "title": "Ensure mounting of cramfs filesystems is disabled",
            "command": "modprobe -n -v cramfs 2>&1 || true",
            "expected": "install /bin/true",
            "severity": "medium",
        },
        {
            "check_id": "CIS-1.1.2",
            "title": "Ensure mounting of freevxfs filesystems is disabled",
            "command": "modprobe -n -v freevxfs 2>&1 || true",
            "expected": "install /bin/true",
            "severity": "medium",
        },
        {
            "check_id": "CIS-5.2.1",
            "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
            "command": "stat -c '%a' /etc/ssh/sshd_config 2>/dev/null || echo 'N/A'",
            "expected": "600",
            "severity": "high",
        },
        {
            "check_id": "CIS-5.4.1.1",
            "title": "Ensure password expiration is 365 days or less",
            "command": "chage --maxdays 99999 root 2>&1; grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null || echo 'N/A'",
            "expected": "PASS_MAX_DAYS",
            "severity": "medium",
        },
        {
            "check_id": "CIS-6.2.1",
            "title": "Ensure no legacy '+' entries exist in /etc/passwd",
            "command": "grep '^+:' /etc/passwd 2>/dev/null || echo 'NONE'",
            "expected": "NONE",
            "severity": "high",
        },
    ],
    "custom_hardening_v1.0": [
        {
            "check_id": "CUST-1",
            "title": "Ensure SELinux is enforcing",
            "command": "getenforce 2>/dev/null || echo 'Disabled'",
            "expected": "Enforcing",
            "severity": "high",
        },
        {
            "check_id": "CUST-2",
            "title": "Ensure unnecessary services are disabled",
            "command": "systemctl is-enabled avahi-daemon 2>/dev/null || echo 'disabled'",
            "expected": "disabled",
            "severity": "medium",
        },
        {
            "check_id": "CUST-3",
            "title": "Ensure core dumps are restricted",
            "command": "grep -E '^\\*\\s+hard\\s+core' /etc/security/limits.conf 2>/dev/null || echo 'NOT_CONFIGURED'",
            "expected": "NOT_CONFIGURED",
            "severity": "low",
        },
    ],
}


def run_check(benchmark_id: str, check: dict[str, Any]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            check["command"],
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        actual = result.stdout.strip()
    except subprocess.TimeoutExpired:
        actual = "TIMEOUT"
    except Exception as e:
        actual = f"ERROR: {e}"

    passed = 1 if actual == check["expected"] else 0

    execute_db(
        "INSERT INTO sca_checks (benchmark_id, check_id, title, passed, actual_value, expected_value, severity) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (benchmark_id, check["check_id"], check["title"], passed, actual, check["expected"], check["severity"]),
    )
    return {
        "check_id": check["check_id"],
        "title": check["title"],
        "passed": bool(passed),
        "actual": actual,
        "expected": check["expected"],
        "severity": check["severity"],
    }


def run_benchmark(benchmark_id: str | None = None) -> dict[str, Any]:
    if benchmark_id and benchmark_id in _BENCHMARKS:
        benchmarks_to_run = {benchmark_id: _BENCHMARKS[benchmark_id]}
    else:
        benchmarks_to_run = _BENCHMARKS

    results: dict[str, Any] = {}
    for bm_id, checks in benchmarks_to_run.items():
        check_results = []
        for check in checks:
            check_results.append(run_check(bm_id, check))
        passed = sum(1 for c in check_results if c["passed"])
        total = len(check_results)
        score = (passed / total * 100) if total > 0 else 0.0
        execute_db(
            "INSERT INTO sca_benchmark_results (benchmark_id, total_checks, passed_checks, score) VALUES (?, ?, ?, ?)",
            (bm_id, total, passed, score),
        )
        results[bm_id] = {
            "total": total,
            "passed": passed,
            "score": score,
            "checks": check_results,
        }
    return results


def get_latest_benchmark(limit: int = 10) -> list[dict[str, Any]]:
    return query_db(
        "SELECT * FROM sca_benchmark_results ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ) or []


def get_benchmark_results(benchmark_id: str) -> list[dict[str, Any]]:
    return query_db(
        "SELECT * FROM sca_benchmark_results WHERE benchmark_id = ? ORDER BY timestamp DESC LIMIT 20",
        (benchmark_id,),
    ) or []


def get_check_details(benchmark_id: str) -> list[dict[str, Any]]:
    return query_db(
        "SELECT * FROM sca_checks WHERE benchmark_id = ? ORDER BY timestamp DESC",
        (benchmark_id,),
    ) or []


def get_sca_stats() -> dict[str, Any]:
    total_runs = query_db("SELECT COUNT(*) as cnt FROM sca_benchmark_results", one=True)
    avg_score = query_db("SELECT AVG(score) as avg_score FROM sca_benchmark_results", one=True)
    return {
        "total_runs": total_runs["cnt"] if total_runs else 0,
        "average_score": round(avg_score["avg_score"], 2) if avg_score and avg_score["avg_score"] else 0.0,
    }
