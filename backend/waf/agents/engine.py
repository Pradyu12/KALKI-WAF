import json
import uuid
from datetime import UTC, datetime

from waf.db import execute_db, query_db


def register_agent(
    hostname: str,
    os_info: str = "",
    ip_address: str = "",
    agent_version: str = "1.0.0",
    tags: str = "[]",
) -> dict:
    agent_id = f"agt-{uuid.uuid4().hex[:12]}"
    now = datetime.now(UTC).isoformat()
    ok = execute_db(
        """INSERT INTO agents (agent_id, hostname, os_info, ip_address, agent_version, status, last_heartbeat, tags)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
        (agent_id, hostname, os_info, ip_address, agent_version, now, tags),
    )
    if not ok:
        return {"error": "Failed to register agent"}
    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "api_key": agent_id,
        "status": "active",
        "message": "Agent registered successfully",
    }


def get_agents() -> list[dict]:
    rows = query_db("SELECT * FROM agents ORDER BY last_heartbeat DESC")
    if rows:
        for r in rows:
            if isinstance(r.get("tags"), str):
                try:
                    r["tags"] = json.loads(r["tags"])
                except (json.JSONDecodeError, TypeError):
                    r["tags"] = []
    return rows or []


def get_agent(agent_id: str) -> dict | None:
    row = query_db("SELECT * FROM agents WHERE agent_id = ?", (agent_id,), one=True)
    if row and isinstance(row.get("tags"), str):
        try:
            row["tags"] = json.loads(row["tags"])
        except (json.JSONDecodeError, TypeError):
            row["tags"] = []
    return row


def submit_agent_heartbeat(agent_id: str, extra: dict | None = None) -> dict:
    agent = get_agent(agent_id)
    if not agent:
        return {"error": "Agent not found"}
    now = datetime.now(UTC).isoformat()
    execute_db("UPDATE agents SET last_heartbeat = ?, status = 'active' WHERE agent_id = ?", (now, agent_id))
    if extra:
        summary = json.dumps(extra)
        execute_db(
            "INSERT INTO agent_results (agent_id, result_type, payload, summary, timestamp) VALUES (?, 'heartbeat', ?, ?, ?)",
            (agent_id, json.dumps(extra), summary, now),
        )
    return {"status": "ok", "last_heartbeat": now}


def submit_agent_result(agent_id: str, result_type: str, payload: dict) -> dict:
    agent = get_agent(agent_id)
    if not agent:
        return {"error": "Agent not found"}
    now = datetime.now(UTC).isoformat()
    payload_str = json.dumps(payload)
    summary = payload.get("summary", "") or json.dumps(payload)[:200]
    ok = execute_db(
        "INSERT INTO agent_results (agent_id, result_type, payload, summary, timestamp) VALUES (?, ?, ?, ?, ?)",
        (agent_id, result_type, payload_str, summary, now),
    )
    if not ok:
        return {"error": "Failed to store result"}
    return {"status": "stored", "timestamp": now}


def get_agent_results(agent_id: str, result_type: str | None = None, limit: int = 50) -> list[dict]:
    if result_type:
        rows = query_db(
            "SELECT * FROM agent_results WHERE agent_id = ? AND result_type = ? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, result_type, limit),
        )
    else:
        rows = query_db(
            "SELECT * FROM agent_results WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, limit),
        )
    for r in rows or []:
        if isinstance(r.get("payload"), str):
            try:
                r["payload"] = json.loads(r["payload"])
            except (json.JSONDecodeError, TypeError):
                pass
    return rows or []


def get_pending_commands_for(agent_id: str) -> list[dict]:
    rows = query_db(
        "SELECT * FROM agent_commands WHERE agent_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 20",
        (agent_id,),
    )
    for r in rows or []:
        if isinstance(r.get("command"), str):
            try:
                r["command"] = json.loads(r["command"])
            except (json.JSONDecodeError, TypeError):
                pass
    return rows or []


def ack_command(command_id: int, agent_id: str, status: str = "delivered") -> dict:
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat()
    ok = execute_db(
        "UPDATE agent_commands SET status = ?, delivered_at = ? WHERE id = ? AND agent_id = ?",
        (status, now, command_id, agent_id),
    )
    return {"status": "ok" if ok else "error"}


def enqueue_command(agent_id: str, command: dict) -> dict:
    cmd_str = json.dumps(command)
    ok = execute_db(
        "INSERT INTO agent_commands (agent_id, command) VALUES (?, ?)",
        (agent_id, cmd_str),
    )
    if not ok:
        return {"error": "Failed to enqueue command"}
    return {"status": "queued"}
