import re
import uuid
import os
from datetime import datetime
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.concurrency import run_in_threadpool

from .database import query_db, execute_db, get_db_connection
from .models import RuleCreate, ToggleRuleRequest, PostureUpdate, SandboxTestRequest
from .config import UPSTREAM_SERVER_URL, RATE_LIMIT_THRESHOLD
from . import middleware

router = APIRouter()

@router.get("/")
async def root():
    return await dashboard()

@router.get("/dashboard")
async def dashboard():
    try:
        with open("index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found")

@router.get("/kalki_waf_logo.png")
async def get_logo():
    if os.path.exists("kalki_waf_logo.png"):
        return FileResponse("kalki_waf_logo.png", media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo asset not found")

@router.get("/api/v1/threat-intel/alerts")
async def get_dashboard_telemetry():
    try:
        return await run_in_threadpool(fetch_telemetry_data)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"SIEM Backend Error: {str(err)}")

def fetch_telemetry_data():
    total_blocked = (query_db("SELECT COUNT(*) as total FROM security_events WHERE mitigation_action = 'Blocked'", one=True) or {'total': 0})['total']
    sqli_count = (query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'SQLi'", one=True) or {'total': 0})['total']
    xss_count = (query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'XSS'", one=True) or {'total': 0})['total']
    anomalous_count = (query_db("SELECT COUNT(*) as total FROM security_events WHERE threat_category = 'Anomalous'", one=True) or {'total': 0})['total']

    incidents = query_db("SELECT incident_id, timestamp, source_ip, threat_category, target_uri, mitigation_action, user_agent, malicious_payload FROM security_events ORDER BY timestamp DESC LIMIT 30") or []
    for inc in incidents:
        if inc['timestamp'] and not isinstance(inc['timestamp'], str):
            inc['timestamp'] = inc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')

    rules = query_db("SELECT * FROM rules") or []
    _, db_type = get_db_connection()

    return {
        "metrics": {
            "total_ingress": total_blocked + 1524,
            "total_blocked": total_blocked,
            "sqli_count": sqli_count,
            "xss_count": xss_count,
            "anomalous_count": anomalous_count,
            "active_rules_count": len(middleware.ACTIVE_RULES_CACHE),
            "posture": middleware.GLOBAL_POSTURE,
            "upstream_url": UPSTREAM_SERVER_URL,
            "rate_limit": RATE_LIMIT_THRESHOLD,
            "db_type": db_type.upper()
        },
        "incidents": incidents,
        "rules": rules
    }

@router.get("/api/v1/rules")
async def get_rules():
    try:
        return await run_in_threadpool(query_db, "SELECT * FROM rules")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/v1/rules")
async def create_rule(rule: RuleCreate):
    pattern = rule.pattern.strip()
    if pattern.startswith('/') and pattern.count('/') >= 2:
        pattern = pattern[1:pattern.rfind('/')]
    try:
        re.compile(pattern, re.IGNORECASE)
    except Exception as regex_err:
        raise HTTPException(status_code=400, detail=f"Invalid regular expression format: {regex_err}")
    rule_id = f"custom-{str(uuid.uuid4())[:8]}"
    query = "INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    args = (rule_id, rule.identifier, pattern, rule.action, rule.category, 1, 0, rule.severity, rule.description)
    if not await run_in_threadpool(execute_db, query, args):
        raise HTTPException(status_code=500, detail="Failed to save rule.")
    await run_in_threadpool(middleware.reload_rules_cache)
    return {"status": "success", "rule_id": rule_id}

@router.put("/api/v1/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, payload: ToggleRuleRequest):
    if not await run_in_threadpool(execute_db, "UPDATE rules SET is_active = %s WHERE rule_id = %s", (1 if payload.is_active else 0, rule_id)):
        raise HTTPException(status_code=500, detail="Failed to toggle rule.")
    await run_in_threadpool(middleware.reload_rules_cache)
    return {"status": "success"}

@router.delete("/api/v1/rules/{rule_id}")
async def delete_rule(rule_id: str):
    if rule_id in ["sql-core-01", "xss-scrutiny-01", "rfi-blocker-01"]:
        raise HTTPException(status_code=403, detail="Forbidden: System default rules cannot be deleted.")
    if not await run_in_threadpool(execute_db, "DELETE FROM rules WHERE rule_id = %s", (rule_id,)):
        raise HTTPException(status_code=500, detail="Failed to delete rule.")
    await run_in_threadpool(middleware.reload_rules_cache)
    return {"status": "success"}

@router.get("/api/v1/mitigation-posture")
async def get_mitigation_posture():
    return {"posture": middleware.GLOBAL_POSTURE}

@router.post("/api/v1/mitigation-posture")
async def update_mitigation_posture(payload: PostureUpdate):
    if payload.posture not in ["Monitor Only", "Standard Posture", "Under Attack"]:
        raise HTTPException(status_code=400, detail="Invalid posture")
    if not await run_in_threadpool(execute_db, "UPDATE mitigation_state SET posture = %s WHERE id = 'global'", (payload.posture,)):
        raise HTTPException(status_code=500, detail="Failed to update posture.")
    await run_in_threadpool(middleware.reload_global_posture)
    return {"status": "success", "posture": middleware.GLOBAL_POSTURE}

@router.post("/api/v1/rules/test-sandbox")
async def test_sandbox(payload: SandboxTestRequest):
    pattern = payload.pattern.strip()
    if pattern.startswith('/') and pattern.count('/') >= 2:
        pattern = pattern[1:pattern.rfind('/')]
    try:
        rx = re.compile(pattern, re.IGNORECASE)
        match = rx.search(payload.payload)
        if match:
            return {"match": True, "span": match.span(), "match_group": match.group(0)}
        return {"match": False}
    except Exception as err:
        return {"match": False, "error": str(err)}
