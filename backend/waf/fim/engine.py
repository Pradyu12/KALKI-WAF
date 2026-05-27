import hashlib
import os
import stat
from datetime import UTC, datetime
from typing import Any

from waf.db import execute_db, query_db

_MONITORED_PATHS: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/selinux/config",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/crontab",
]

_EXTRA_PATTERNS: list[str] = []


def set_monitored_paths(paths: list[str]):
    global _MONITORED_PATHS
    _MONITORED_PATHS = paths


def add_monitor_pattern(pattern: str):
    _EXTRA_PATTERNS.append(pattern)


def _file_hash(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _file_permissions(path: str) -> str | None:
    try:
        mode = os.stat(path).st_mode
        return stat.filemode(mode)
    except (OSError, PermissionError):
        return None


def record_baseline(path: str):
    file_hash = _file_hash(path)
    perms = _file_permissions(path)
    if file_hash:
        execute_db(
            "INSERT OR REPLACE INTO fim_baseline (file_path, file_hash, permissions) VALUES (?, ?, ?)",
            (path, file_hash, perms),
        )


def record_baselines_for(paths: list[str] | None = None):
    targets = paths or _MONITORED_PATHS + _EXTRA_PATTERNS
    for path in targets:
        if os.path.isfile(path):
            record_baseline(path)


def check_integrity(path: str) -> dict[str, Any] | None:
    baseline = query_db(
        "SELECT * FROM fim_baseline WHERE file_path = ?", (path,), one=True
    )
    if not baseline:
        record_baseline(path)
        return None

    current_hash = _file_hash(path)
    current_perms = _file_permissions(path)

    if not os.path.isfile(path):
        execute_db(
            "INSERT INTO fim_events (file_path, change_type, old_hash, new_hash, old_permissions, new_permissions) "
            "VALUES (?, 'deleted', ?, NULL, ?, NULL)",
            (path, baseline["file_hash"], baseline["permissions"]),
        )
        execute_db("DELETE FROM fim_baseline WHERE file_path = ?", (path,))
        return {
            "file_path": path,
            "change_type": "deleted",
            "old_hash": baseline["file_hash"],
            "old_permissions": baseline["permissions"],
            "new_hash": None,
            "new_permissions": None,
        }

    changes = []
    if current_hash and current_hash != baseline["file_hash"]:
        changes.append("hash")
    if current_perms and current_perms != baseline.get("permissions"):
        changes.append("permissions")

    if changes:
        execute_db(
            "INSERT INTO fim_events (file_path, change_type, old_hash, new_hash, old_permissions, new_permissions) "
            "VALUES (?, 'modified', ?, ?, ?, ?)",
            (path, baseline["file_hash"], current_hash, baseline["permissions"], current_perms),
        )
        execute_db(
            "UPDATE fim_baseline SET file_hash = ?, permissions = ?, last_checked = CURRENT_TIMESTAMP WHERE file_path = ?",
            (current_hash, current_perms, path),
        )
        return {
            "file_path": path,
            "change_type": "modified",
            "old_hash": baseline["file_hash"],
            "new_hash": current_hash,
            "old_permissions": baseline["permissions"],
            "new_permissions": current_perms,
            "changes": changes,
        }
    return None


def run_integrity_check(paths: list[str] | None = None) -> list[dict[str, Any]]:
    targets = paths or _MONITORED_PATHS + _EXTRA_PATTERNS
    results = []
    for path in targets:
        if os.path.isfile(path):
            result = check_integrity(path)
            if result:
                results.append(result)
    return results


def get_fim_events(
    limit: int = 50, offset: int = 0, change_type: str | None = None
) -> list[dict[str, Any]]:
    if change_type:
        rows = query_db(
            "SELECT * FROM fim_events WHERE change_type = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (change_type, limit, offset),
        )
    else:
        rows = query_db(
            "SELECT * FROM fim_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
    return rows or []


def get_fim_stats() -> dict[str, Any]:
    total = query_db("SELECT COUNT(*) as cnt FROM fim_events", one=True)
    by_type = query_db(
        "SELECT change_type, COUNT(*) as cnt FROM fim_events GROUP BY change_type"
    )
    monitored = query_db("SELECT COUNT(*) as cnt FROM fim_baseline", one=True)
    return {
        "total_events": total["cnt"] if total else 0,
        "monitored_files": monitored["cnt"] if monitored else 0,
        "by_change_type": {r["change_type"]: r["cnt"] for r in by_type} if by_type else {},
    }
