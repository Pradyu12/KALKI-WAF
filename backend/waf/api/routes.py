import asyncio
import json
import os
import re
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from waf import state
from waf.api.auth import verify_admin_key
from waf.core.metrics import metrics_endpoint
from waf.core.telemetry import fetch_telemetry_data
from waf.core.websocket import manager
from waf.db import execute_db, query_db
from waf.rules.engine import reload_global_posture, reload_rules_cache
from waf.rules.models import IPBlacklistRequest, PostureUpdate, RuleCreate, SandboxTestRequest, ToggleRuleRequest

router = APIRouter()

_FRONTEND_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "frontend")
)

PROTECTED_RULE_IDS = {"sql-core-01", "xss-scrutiny-01", "rfi-blocker-01"}


@router.get("/health")
async def health():
    """Liveness probe — returns 200 if the process is alive."""
    return {"status": "healthy", "service": "kalki-waf", "version": "2.0.0"}


@router.get("/readyz")
async def readiness():
    """Readiness probe — checks database connectivity."""
    from waf.db import query_db

    try:
        row = query_db("SELECT COUNT(*) as cnt FROM rules", one=True)
        if row is not None:
            return {"status": "ready", "database": "connected"}
        return {"status": "degraded", "database": "empty"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}") from e


@router.get("/metrics")
async def metrics():
    return await metrics_endpoint()


@router.websocket("/api/v1/ws/incidents")
async def websocket_endpoint(websocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except Exception:
        manager.disconnect(websocket)


@router.get("/")
async def root():
    return await dashboard()


@router.get("/dashboard")
async def dashboard():
    path = os.path.join(_FRONTEND_DIR, "dashboard.html")
    try:
        with open(path) as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found") from None


@router.get("/earth.jpg")
async def earth_texture():
    path = os.path.join(_FRONTEND_DIR, "static", "earth.jpg")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return Response(content=f.read(), media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="Earth texture not found")


@router.get("/kalki_waf_logo.png")
async def get_logo():
    path = os.path.join(_FRONTEND_DIR, "kalki_waf_logo.png")
    try:
        if os.path.exists(path):
            with open(path, "rb") as f:
                content = f.read()
            return Response(content=content, media_type="image/png")
    except Exception as e:
        print(f"[ERROR] Failed to serve logo: {e}")
    raise HTTPException(status_code=404, detail="Logo asset not found")


@router.get("/api/v1/threat-intel/alerts")
async def get_dashboard_telemetry():
    try:
        return await run_in_threadpool(fetch_telemetry_data)
    except Exception as err:
        import sys
        import traceback as _tb

        _tb.print_exc(file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"SIEM Backend Error: {str(err)}") from err


@router.get("/api/v1/rules")
async def get_rules():
    try:
        rules = await run_in_threadpool(query_db, "SELECT * FROM rules")
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/api/v1/rules")
async def create_rule(rule: RuleCreate, _: str | None = Depends(verify_admin_key)):
    pattern = rule.pattern.strip()
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash_idx = pattern.rfind("/")
        pattern = pattern[1:last_slash_idx]

    try:
        re.compile(pattern, re.IGNORECASE)
    except Exception as regex_err:
        raise HTTPException(status_code=400, detail=f"Invalid regular expression format: {regex_err}") from None

    rule_id = f"custom-{str(uuid.uuid4())[:8]}"

    query = """
        INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """  # noqa: E501
    args = (rule_id, rule.identifier, pattern, rule.action, rule.category, 1, 0, rule.severity, rule.description)

    success = await run_in_threadpool(execute_db, query, args)
    if not success:
        raise HTTPException(
            status_code=500, detail="Failed to save custom signature profile to database. Check for duplicates."
        )  # noqa: E501

    await run_in_threadpool(reload_rules_cache)
    return {
        "status": "success",
        "message": "Signature profile compiled and hot-patched successfully",
        "rule_id": rule_id,
    }  # noqa: E501


@router.put("/api/v1/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, payload: ToggleRuleRequest, _: str | None = Depends(verify_admin_key)):
    is_active_val = 1 if payload.is_active else 0
    query = "UPDATE rules SET is_active = ? WHERE rule_id = ?"
    success = await run_in_threadpool(execute_db, query, (is_active_val, rule_id))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to toggle ruleset activity profile.")

    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": "Security ruleset updated successfully."}


@router.delete("/api/v1/rules/{rule_id}")
async def delete_rule(rule_id: str, _: str | None = Depends(verify_admin_key)):
    if rule_id in PROTECTED_RULE_IDS:
        raise HTTPException(status_code=403, detail="Forbidden: System default signature rulesets cannot be deleted.")

    query = "DELETE FROM rules WHERE rule_id = ?"
    success = await run_in_threadpool(execute_db, query, (rule_id,))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to wipe rule from database registry.")

    await run_in_threadpool(reload_rules_cache)
    return {"status": "success", "message": "Signature wiped from engine memory."}


@router.get("/api/v1/mitigation-posture")
async def get_mitigation_posture():
    return {"posture": state.GLOBAL_POSTURE}


@router.post("/api/v1/mitigation-posture")
async def update_mitigation_posture(payload: PostureUpdate, _: str | None = Depends(verify_admin_key)):
    if payload.posture not in ["Monitor Only", "Standard Posture", "Under Attack"]:
        raise HTTPException(status_code=400, detail="Invalid posture specification")

    query = "UPDATE mitigation_state SET posture = ? WHERE id = 'global'"
    success = await run_in_threadpool(execute_db, query, (payload.posture,))
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update posture parameter in database settings.")

    await run_in_threadpool(reload_global_posture)
    return {"status": "success", "message": f"Global WAF threat posture updated to: {state.GLOBAL_POSTURE}"}


@router.post("/api/v1/rules/test-sandbox")
async def test_sandbox(payload: SandboxTestRequest):
    pattern = payload.pattern.strip()
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash_idx = pattern.rfind("/")
        pattern = pattern[1:last_slash_idx]

    try:
        rx = re.compile(pattern, re.IGNORECASE)
        match = rx.search(payload.payload)
        if match:
            return {"match": True, "span": match.span(), "match_group": match.group(0)}
        return {"match": False}
    except Exception as err:
        return {"match": False, "error": str(err)}


@router.get("/api/v1/stream")
async def live_stream():
    async def event_generator():
        while True:
            try:
                data = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "metrics": state.LIVE_STATS,
                    "posture": state.GLOBAL_POSTURE,
                    "active_rules": len(state.ACTIVE_RULES_CACHE),
                }
                yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(2)
            except Exception:
                await asyncio.sleep(5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/api/v1/telemetry/live")
async def live_telemetry():
    return {
        "cpu_percent": round(state.LIVE_STATS.get("cpu_percent", 0), 1),
        "memory_mb": state.LIVE_STATS.get("memory_mb", 0),
        "requests_per_second": round(state.LIVE_STATS.get("requests_per_second", 0), 2),
        "active_rules": len(state.ACTIVE_RULES_CACHE),
        "posture": state.GLOBAL_POSTURE,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def log_console(message: str):
    print(f"[{datetime.now(UTC).isoformat()}] {message}")


@router.get("/api/v1/geo/lookup")
async def geo_lookup(ip: str):
    from waf.security.geoip import get_geo_location
    return {"ip": ip, "geo": get_geo_location(ip)}


@router.get("/api/v1/firewall/location")
async def firewall_location():
    from waf.config import FIREWALL_LABEL, FIREWALL_LAT, FIREWALL_LON
    return {
        "lat": FIREWALL_LAT,
        "lon": FIREWALL_LON,
        "label": FIREWALL_LABEL,
    }


@router.post("/api/v1/blacklist")
async def add_to_blacklist(request: IPBlacklistRequest, _: str | None = Depends(verify_admin_key)):
    state.IP_BLACKLIST.add(request.ip_address)
    log_console(f"IP_BLACKLIST: Added {request.ip_address} - {request.reason}")
    return {"status": "success", "message": f"IP {request.ip_address} blacklisted"}


@router.get("/api/v1/blacklist")
async def get_blacklist():
    return {"blacklisted_ips": list(state.IP_BLACKLIST)}


@router.delete("/api/v1/blacklist/{ip}")
async def remove_from_blacklist(ip: str, _: str | None = Depends(verify_admin_key)):
    state.IP_BLACKLIST.discard(ip)
    return {"status": "success", "message": f"IP {ip} removed from blacklist"}
