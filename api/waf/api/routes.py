import asyncio
import json
import os
import re
import uuid
from datetime import datetime

try:
    from datetime import UTC
except ImportError:
    UTC = UTC

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from waf import state
from waf.api.auth import verify_admin_key
from waf.core.metrics import metrics_endpoint
from waf.core.telemetry import fetch_telemetry_data
from waf.core.websocket import manager
from waf.db import execute_db, query_db
from waf.rules.engine import reload_global_posture, reload_rules_cache
from waf.rules.models import (
    ImportRulesRequest,
    IPBlacklistRequest,
    PostureUpdate,
    RuleCreate,
    SandboxMatchRequest,
    SandboxTestRequest,
    ToggleRuleRequest,
)

router = APIRouter()

_FRONTEND_DIR: str = ""
_dashboard_html: str | None = None


def _resolve_frontend():
    global _FRONTEND_DIR, _dashboard_html
    candidates = [
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "dashboard")),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "dashboard")),
        os.path.normpath(os.path.join(os.getcwd(), "..", "dashboard")),
        os.path.normpath(os.path.join(os.getcwd(), "dashboard")),
        "/app/dashboard",
        "/app/api/dashboard",
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "dashboard")),
    ]
    for d in candidates:
        p = os.path.join(d, "index.html")
        if os.path.isfile(p):
            _FRONTEND_DIR = d
            _dashboard_html = p
            return
    _FRONTEND_DIR = candidates[0]


_resolve_frontend()

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
    global _dashboard_html, _FRONTEND_DIR
    if not _dashboard_html or not os.path.isfile(_dashboard_html):
        _resolve_frontend()
    p = _dashboard_html or os.path.join(_FRONTEND_DIR, "index.html")
    try:
        with open(p) as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found") from None


@router.get("/earth.jpg")
async def earth_texture():
    path = os.path.join(_FRONTEND_DIR, "earth.jpg")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return Response(content=f.read(), media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="Earth texture not found")


@router.get("/kalki_waf_logo.svg")
async def get_logo_svg():
    path = os.path.join(_FRONTEND_DIR, "kalki_waf_logo.svg")
    try:
        if os.path.exists(path):
            with open(path) as f:
                content = f.read()
            return Response(content=content, media_type="image/svg+xml")
    except Exception as e:
        print(f"[ERROR] Failed to serve SVG logo: {e}")
    raise HTTPException(status_code=404, detail="SVG logo not found")


@router.get("/kalki_waf_logo.png")
async def get_logo_png():
    path = os.path.join(_FRONTEND_DIR, "kalki_waf_logo.png")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return Response(content=f.read(), media_type="image/png")
    raise HTTPException(status_code=404, detail="PNG logo not found")


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


@router.post("/api/v1/rules/import")
async def import_rules(request: Request, _: str | None = Depends(verify_admin_key)):
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()

    try:
        raw = yaml.safe_load(body) if "yaml" in content_type or "x-yaml" in content_type else json.loads(body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse request body: {e}") from None

    rules_raw = raw if isinstance(raw, list) else raw.get("rules", [])
    if not isinstance(rules_raw, list) or not rules_raw:
        raise HTTPException(status_code=400, detail="Request must contain a 'rules' list")

    overwrite = raw.get("overwrite", False) if isinstance(raw, dict) else False

    imported_count = 0
    skipped_count = 0
    errors: list[dict] = []

    for i, entry in enumerate(rules_raw):
        try:
            item = ImportRulesRequest(rules=[entry]).rules[0]
        except Exception as ve:
            errors.append({"index": i, "error": str(ve)})
            skipped_count += 1
            continue

        if not item.pattern.strip():
            errors.append({"index": i, "error": "Empty pattern"})
            skipped_count += 1
            continue

        try:
            re.compile(item.pattern, re.IGNORECASE)
        except re.error as re_err:
            errors.append({"index": i, "identifier": item.identifier, "error": f"Invalid regex: {re_err}"})
            skipped_count += 1
            continue

        rule_id = item.identifier
        existing = query_db("SELECT rule_id FROM rules WHERE identifier = ?", (item.identifier,), one=True)
        if existing:
            if overwrite:
                execute_db(
                    """UPDATE rules SET pattern=?, action=?, category=?, severity=?, description=? WHERE identifier=?""",
                    (item.pattern, item.action, item.category, item.severity, item.description, item.identifier),
                )
                imported_count += 1
            else:
                skipped_count += 1
            continue

        import uuid as _uuid

        rule_id = f"import-{item.identifier}-{str(_uuid.uuid4())[:6]}"

        execute_db(
            """INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
               VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)""",
            (rule_id, item.identifier, item.pattern, item.action, item.category, item.severity, item.description),
        )
        imported_count += 1

    if imported_count > 0:
        await run_in_threadpool(reload_rules_cache)

    msg = f"Imported {imported_count} rule(s)"
    if skipped_count:
        msg += f", {skipped_count} skipped"
    return {
        "status": "success",
        "message": msg,
        "imported": imported_count,
        "skipped": skipped_count,
        "errors": errors if errors else None,
    }


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


@router.post("/api/v1/sandbox/match")
async def sandbox_match(req: SandboxMatchRequest):
    from waf import state

    results = []
    for rule in state.ACTIVE_RULES_CACHE:
        if req.category and rule.get("category", "").lower() != req.category.lower():
            continue
        pattern = rule["pattern"]
        try:
            rx = re.compile(pattern, re.IGNORECASE)
            m = rx.search(req.payload)
            if m:
                results.append(
                    {
                        "rule_id": rule["rule_id"],
                        "category": rule.get("category", ""),
                        "rule": rule.get("identifier", rule["rule_id"]),
                        "confidence": rule.get("severity", "Level 2"),
                    }
                )
        except Exception:
            pass
    return {"matched": results, "count": len(results)}


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
async def live_stream(request: Request):
    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                data = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "metrics": state.LIVE_STATS,
                    "posture": state.GLOBAL_POSTURE,
                    "active_rules": len(state.ACTIVE_RULES_CACHE),
                }
                yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass

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
    from datetime import timedelta

    state.IP_BLACKLIST.add(request.ip_address)
    expires_at = (datetime.now(UTC) + timedelta(hours=request.duration_hours)).strftime("%Y-%m-%d %H:%M:%S")
    execute_db(
        """INSERT OR REPLACE INTO ip_blacklist (ip_address, reason, created_by, expires_at)
           VALUES (?, ?, 'admin', ?)""",
        (request.ip_address, request.reason, expires_at),
    )
    log_audit("blacklist_add", "ip", request.ip_address, details=f"Reason: {request.reason}")
    log_console(f"IP_BLACKLIST: Added {request.ip_address} - {request.reason} (expires {expires_at})")
    return {"status": "success", "message": f"IP {request.ip_address} blacklisted until {expires_at}"}


@router.get("/api/v1/blacklist")
async def get_blacklist(limit: int = 100, offset: int = 0):
    rows = query_db(
        "SELECT * FROM ip_blacklist WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    count_row = query_db(
        "SELECT COUNT(*) as cnt FROM ip_blacklist WHERE expires_at IS NULL OR expires_at > datetime('now')", one=True
    )
    return {
        "blacklisted_ips": [r["ip_address"] for r in (rows or [])],
        "entries": rows or [],
        "total": count_row["cnt"] if count_row else 0,
    }


@router.delete("/api/v1/blacklist/{ip}")
async def remove_from_blacklist(ip: str, _: str | None = Depends(verify_admin_key)):
    state.IP_BLACKLIST.discard(ip)
    execute_db("DELETE FROM ip_blacklist WHERE ip_address = ?", (ip,))
    log_audit("blacklist_remove", "ip", ip)
    return {"status": "success", "message": f"IP {ip} removed from blacklist"}


@router.get("/api/v1/blacklist/cleanup")
async def cleanup_blacklist(_: str | None = Depends(verify_admin_key)):
    rows = query_db(
        "SELECT ip_address FROM ip_blacklist WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
    )
    if rows:
        for r in rows:
            state.IP_BLACKLIST.discard(r["ip_address"])
        execute_db("DELETE FROM ip_blacklist WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')")
    log_audit("blacklist_cleanup", "system", "expired")
    return {"status": "success", "cleaned": len(rows) if rows else 0}


# ─── Audit Log ──────────────────────────────────────────────────────────────────────


def log_audit(
    action: str,
    target_type: str = "",
    target_id: str = "",
    actor: str = "system",
    details: str = "",
    ip_address: str = "",
):
    execute_db(
        """INSERT INTO audit_log (action, target_type, target_id, actor, details, ip_address)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (action, target_type, target_id, actor, details, ip_address),
    )


@router.get("/api/v1/audit/log")
async def get_audit_log(limit: int = 50, offset: int = 0, action: str | None = None):
    if action:
        rows = query_db(
            "SELECT * FROM audit_log WHERE action = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (action, limit, offset),
        )
        count_row = query_db("SELECT COUNT(*) as cnt FROM audit_log WHERE action = ?", (action,), one=True)
    else:
        rows = query_db("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
        count_row = query_db("SELECT COUNT(*) as cnt FROM audit_log", one=True)
    return {
        "entries": rows or [],
        "total": count_row["cnt"] if count_row else 0,
        "limit": limit,
        "offset": offset,
    }


# ─── SIEM (Security Information & Event Management) ──────────────────────────────


@router.get("/api/v1/siem/alerts")
async def siem_get_alerts(severity: str | None = None, limit: int = 50, offset: int = 0, unacked: bool = False):
    from waf.siem.engine import get_alerts

    return await run_in_threadpool(get_alerts, severity, limit, offset, unacked)


@router.post("/api/v1/siem/alerts/{alert_id}/ack")
async def siem_ack_alert(alert_id: int, _: str | None = Depends(verify_admin_key)):
    from waf.siem.engine import acknowledge_alert

    success = await run_in_threadpool(acknowledge_alert, alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "success"}


@router.get("/api/v1/siem/stats")
async def siem_stats():
    from waf.siem.engine import get_alert_stats

    return await run_in_threadpool(get_alert_stats)


@router.post("/api/v1/siem/ingest")
async def siem_ingest(source: str, log_type: str, content: str, severity: str = "info"):
    from waf.siem.engine import ingest_log

    rid = await run_in_threadpool(ingest_log, source, log_type, content, severity)
    return {"status": "ingested", "alert_id": rid}


@router.post("/api/v1/siem/correlate")
async def siem_correlate(window: int = 5):
    from waf.siem.engine import correlate_events

    return {"correlations": await run_in_threadpool(correlate_events, window)}


@router.post("/api/v1/siem/run-detection")
async def siem_run_detection(_: str | None = Depends(verify_admin_key)):
    from waf.siem.engine import run_detection_rules

    triggered = await run_in_threadpool(run_detection_rules)
    return {"alerts_triggered": len(triggered), "alerts": triggered}


# ─── HIDS (Host-based Intrusion Detection) ────────────────────────────────────────


@router.get("/api/v1/hids/alerts")
async def hids_get_alerts(severity: str | None = None, log_type: str | None = None, limit: int = 50, offset: int = 0):
    from waf.hids.engine import get_hids_alerts

    return await run_in_threadpool(get_hids_alerts, severity, log_type, limit, offset)


@router.get("/api/v1/hids/stats")
async def hids_stats():
    from waf.hids.engine import get_hids_stats

    return await run_in_threadpool(get_hids_stats)


@router.post("/api/v1/hids/ingest")
async def hids_ingest(line: str, source: str = "system"):
    from waf.hids.engine import ingest_log_line

    result = await run_in_threadpool(ingest_log_line, line, source)
    return {"parsed": result is not None, "alert": result}


@router.post("/api/v1/hids/bruteforce-check")
async def hids_bruteforce_check(source_ip: str):
    from waf.hids.engine import add_failure, detect_bruteforce

    add_failure(source_ip)
    alert = await run_in_threadpool(detect_bruteforce, source_ip)
    return {"bruteforce_detected": alert is not None, "alert": alert}


# ─── FIM (File Integrity Monitoring) ──────────────────────────────────────────────


@router.get("/api/v1/fim/events")
async def fim_get_events(limit: int = 50, offset: int = 0, change_type: str | None = None):
    from waf.fim.engine import get_fim_events

    return await run_in_threadpool(get_fim_events, limit, offset, change_type)


@router.get("/api/v1/fim/stats")
async def fim_stats():
    from waf.fim.engine import get_fim_stats

    return await run_in_threadpool(get_fim_stats)


@router.post("/api/v1/fim/record-baseline")
async def fim_record_baseline(_: str | None = Depends(verify_admin_key)):
    from waf.fim.engine import _MONITORED_PATHS, record_baselines_for

    await run_in_threadpool(record_baselines_for, _MONITORED_PATHS)
    return {"status": "success", "message": "Baseline recorded for monitored files"}


@router.post("/api/v1/fim/run-check")
async def fim_run_check(path: str | None = None, _: str | None = Depends(verify_admin_key)):
    from waf.fim.engine import check_integrity, run_integrity_check

    if path:
        result = await run_in_threadpool(check_integrity, path)
        return {"changed": result is not None, "event": result}
    results = await run_in_threadpool(run_integrity_check)
    return {"changed": len(results), "events": results}


# ─── SCA (Security Configuration Assessment) ─────────────────────────────────────


@router.post("/api/v1/sca/run")
async def sca_run(benchmark_id: str | None = None, _: str | None = Depends(verify_admin_key)):
    from waf.sca.engine import run_benchmark

    return await run_in_threadpool(run_benchmark, benchmark_id)


@router.get("/api/v1/sca/results")
async def sca_results(benchmark_id: str | None = None):
    from waf.sca.engine import get_benchmark_results, get_latest_benchmark

    if benchmark_id:
        return await run_in_threadpool(get_benchmark_results, benchmark_id)
    return await run_in_threadpool(get_latest_benchmark)


@router.get("/api/v1/sca/checks")
async def sca_checks(benchmark_id: str):
    from waf.sca.engine import get_check_details

    return await run_in_threadpool(get_check_details, benchmark_id)


@router.get("/api/v1/sca/stats")
async def sca_stats():
    from waf.sca.engine import get_sca_stats

    return await run_in_threadpool(get_sca_stats)


# ─── Vulnerability Detection ──────────────────────────────────────────────────────


@router.post("/api/v1/vuln/scan")
async def vuln_scan(_: str | None = Depends(verify_admin_key)):
    from waf.vulnerability.engine import scan_for_vulnerabilities

    return await run_in_threadpool(scan_for_vulnerabilities)


@router.get("/api/v1/vuln/list")
async def vuln_list(severity: str | None = None, limit: int = 50):
    from waf.vulnerability.engine import get_vulnerabilities

    return await run_in_threadpool(get_vulnerabilities, severity, limit)


@router.get("/api/v1/vuln/stats")
async def vuln_stats():
    from waf.vulnerability.engine import get_vuln_stats

    return await run_in_threadpool(get_vuln_stats)


@router.get("/api/v1/vuln/inventory")
async def vuln_inventory():
    from waf.vulnerability.engine import get_software_inventory

    return await run_in_threadpool(get_software_inventory)


# ─── Active Response ──────────────────────────────────────────────────────────────


@router.get("/api/v1/response/playbooks")
async def response_list_playbooks():
    from waf.active_response.engine import list_playbooks

    return await run_in_threadpool(list_playbooks)


@router.post("/api/v1/response/execute")
async def response_execute(
    playbook_id: str, target: str, rule_id: str | None = None, _: str | None = Depends(verify_admin_key)
):
    from waf.active_response.engine import execute_playbook

    return await run_in_threadpool(execute_playbook, playbook_id, target, rule_id)


@router.get("/api/v1/response/log")
async def response_log(limit: int = 50):
    from waf.active_response.engine import get_response_log

    return await run_in_threadpool(get_response_log, limit)


@router.get("/api/v1/response/stats")
async def response_stats():
    from waf.active_response.engine import get_response_stats

    return await run_in_threadpool(get_response_stats)


# ─── Unified SIEM/XDR Dashboard ────────────────────────────────────────────────────


@router.get("/api/v1/siem/dashboard")
async def siem_dashboard():
    from waf.active_response.engine import get_response_stats
    from waf.fim.engine import get_fim_stats
    from waf.hids.engine import get_hids_stats
    from waf.siem.engine import get_alert_stats
    from waf.vulnerability.engine import get_vuln_stats

    siem_stats, hids_stats_data, fim_stats_data, vuln_stats_data, resp_stats = await asyncio.gather(
        run_in_threadpool(get_alert_stats),
        run_in_threadpool(get_hids_stats),
        run_in_threadpool(get_fim_stats),
        run_in_threadpool(get_vuln_stats),
        run_in_threadpool(get_response_stats),
    )
    return {
        "posture": state.GLOBAL_POSTURE,
        "siem": siem_stats,
        "hids": hids_stats_data,
        "fim": fim_stats_data,
        "vulnerability": vuln_stats_data,
        "active_response": resp_stats,
        "live_stats": state.LIVE_STATS,
    }
