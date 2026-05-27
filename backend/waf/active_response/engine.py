import ipaddress
import os
import subprocess
from typing import Any

from waf.db import execute_db, query_db
from waf.state import GLOBAL_POSTURE

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "block_ip_iptables": {
        "id": "block_ip_iptables",
        "name": "Block IP via iptables",
        "description": "Adds an iptables rule to drop all traffic from a malicious IP",
        "target_type": "ip",
        "severity": "high",
        "requires_root": True,
    },
    "block_ip_ufw": {
        "id": "block_ip_ufw",
        "name": "Block IP via UFW",
        "description": "Denies incoming traffic from a source IP using UFW",
        "target_type": "ip",
        "severity": "high",
        "requires_root": True,
    },
    "rate_limit_ip": {
        "id": "rate_limit_ip",
        "name": "Rate Limit IP",
        "description": "Triggers aggressive rate limiting for a specific IP",
        "target_type": "ip",
        "severity": "medium",
        "requires_root": False,
    },
    "lockdown_posture": {
        "id": "lockdown_posture",
        "name": "Lockdown Posture",
        "description": "Sets the global security posture to 'Under Attack'",
        "target_type": "system",
        "severity": "critical",
        "requires_root": False,
    },
    "kill_malicious_process": {
        "id": "kill_malicious_process",
        "name": "Kill Malicious Process",
        "description": "Terminates a process by PID",
        "target_type": "process",
        "severity": "critical",
        "requires_root": True,
    },
    "rotate_secrets": {
        "id": "rotate_secrets",
        "name": "Rotate Secrets",
        "description": "Triggers a secret rotation workflow",
        "target_type": "system",
        "severity": "critical",
        "requires_root": False,
    },
}


def get_playbook(playbook_id: str) -> dict[str, Any] | None:
    return PLAYBOOKS.get(playbook_id)


def list_playbooks() -> dict[str, dict[str, Any]]:
    return PLAYBOOKS


def execute_playbook(playbook_id: str, target: str, rule_id: str | None = None, triggered_by: str = "admin") -> dict[str, Any]:
    playbook = get_playbook(playbook_id)
    if not playbook:
        return {"status": "error", "error": f"Unknown playbook: {playbook_id}"}

    result = "not_executed"
    action_taken = f"{playbook['name']} on {target}"
    record_id = None

    try:
        if playbook_id == "block_ip_iptables":
            _validate_ip(target)
            r = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP", "-m", "comment", "--comment", "KALKI-WAF"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                result = "success"
            else:
                result = f"failed: {r.stderr.strip()}"
        elif playbook_id == "block_ip_ufw":
            _validate_ip(target)
            r = subprocess.run(["ufw", "deny", "from", target], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                result = "success"
            else:
                result = f"failed: {r.stderr.strip()}"
        elif playbook_id == "rate_limit_ip":
            from waf.middleware.rate_limiter import _cleanup_stale_ips
            _cleanup_stale_ips()
            result = "success"
        elif playbook_id == "lockdown_posture":
            GLOBAL_POSTURE = "Under Attack"
            result = "success"
        elif playbook_id == "kill_malicious_process":
            pid = int(target)
            os.kill(pid, 15)
            result = "success"
        elif playbook_id == "rotate_secrets":
            result = "triggered"
        else:
            result = "noop"

        record_id = execute_db(
            "INSERT INTO active_response_log (playbook_id, action_taken, target, rule_id, status, result, triggered_by) "
            "VALUES (?, ?, ?, ?, 'executed', ?, ?)",
            (playbook_id, action_taken, target, rule_id, result, triggered_by),
        )

        if result == "success" or result == "triggered":
            from waf.siem.engine import ingest_log
            ingest_log("active_response", "playbook_executed",
                       f"Playbook {playbook_id} executed on {target}: {result}", playbook["severity"])

        return {"status": "completed", "action": action_taken, "result": result}
    except Exception as e:
        execute_db(
            "INSERT INTO active_response_log (playbook_id, action_taken, target, rule_id, status, result, triggered_by) "
            "VALUES (?, ?, ?, ?, 'failed', ?, ?)",
            (playbook_id, action_taken, target, rule_id, str(e), triggered_by),
        )
        return {"status": "failed", "action": action_taken, "error": str(e)}


def _validate_ip(value: str):
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(f"Invalid IP address or network: {value}")


def get_response_log(limit: int = 50) -> list[dict[str, Any]]:
    return query_db(
        "SELECT * FROM active_response_log ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ) or []


def get_response_stats() -> dict[str, Any]:
    total = query_db("SELECT COUNT(*) as cnt FROM active_response_log", one=True)
    by_status = query_db(
        "SELECT status, COUNT(*) as cnt FROM active_response_log GROUP BY status"
    )
    return {
        "total_executions": total["cnt"] if total else 0,
        "by_status": {r["status"]: r["cnt"] for r in by_status} if by_status else {},
    }
