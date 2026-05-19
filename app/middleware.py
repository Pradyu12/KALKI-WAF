import re
import time
import uuid
from datetime import datetime
from typing import Dict, Any
import httpx
from fastapi import Request, Response, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.concurrency import run_in_threadpool

from .database import query_db, execute_db
from .config import UPSTREAM_SERVER_URL, RATE_LIMIT_THRESHOLD, RATE_LIMIT_WINDOW

ACTIVE_RULES_CACHE = []
GLOBAL_POSTURE = "Standard Posture"
request_history = {}
http_client = httpx.AsyncClient()

def reload_rules_cache():
    global ACTIVE_RULES_CACHE
    rules = query_db("SELECT * FROM rules WHERE is_active = 1")
    cache = []
    if rules:
        for r in rules:
            try:
                pattern = r['pattern']
                compiled = re.compile(pattern, re.IGNORECASE)
                cache.append({
                    "rule_id": r['rule_id'],
                    "identifier": r['identifier'],
                    "pattern": pattern,
                    "action": r['action'],
                    "category": r['category'],
                    "compiled_regex": compiled
                })
            except Exception as e:
                print(f"[WARN] Failed to compile regex for security profile '{r['identifier']}': {e}")
    ACTIVE_RULES_CACHE = cache

def reload_global_posture():
    global GLOBAL_POSTURE
    row = query_db("SELECT posture FROM mitigation_state WHERE id = 'global'", one=True)
    if row:
        GLOBAL_POSTURE = row['posture']
    else:
        GLOBAL_POSTURE = "Standard Posture"

def check_rate_limit(client_ip: str) -> bool:
    current_time = time.time()
    if client_ip not in request_history:
        request_history[client_ip] = []
    request_history[client_ip] = [req_time for req_time in request_history[client_ip]
                                  if current_time - req_time < RATE_LIMIT_WINDOW]
    limit = RATE_LIMIT_THRESHOLD
    if GLOBAL_POSTURE == "Under Attack":
        limit = 10
    if len(request_history[client_ip]) >= limit:
        return False
    request_history[client_ip].append(current_time)
    return True

def log_incident_to_db(event_data: Dict[str, Any]):
    query = """
        INSERT INTO security_events
        (incident_id, timestamp, source_ip, user_agent, target_uri, malicious_payload, threat_category, mitigation_action)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    args = (
        event_data['incident_id'],
        event_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(event_data['timestamp'], datetime) else event_data['timestamp'],
        event_data['source_ip'],
        event_data['user_agent'],
        event_data['target_uri'],
        event_data['malicious_payload'],
        event_data['threat_category'],
        event_data['mitigation_action']
    )
    execute_db(query, args)

def generate_block_page(incident_id: str, client_ip: str, category: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>403 Forbidden - KALKI Security Mitigation Active</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #010103; color: #e4e1e9; padding: 10% 5%; text-align: center; }}
            .container {{ max-width: 600px; margin: 0 auto; background: rgba(15, 23, 42, 0.45); backdrop-filter: blur(12px); padding: 40px; border-radius: 8px; border: 1px solid rgba(255, 0, 60, 0.3); border-top: 4px solid #ff003c; box-shadow: 0 4px 20px rgba(255, 0, 60, 0.15); }}
            h1 {{ color: #ff003c; font-size: 24px; margin-bottom: 10px; font-weight: 700; letter-spacing: -0.02em; }}
            p {{ color: #b9cacb; font-size: 14px; line-height: 1.6; }}
            .details {{ background: #0e0e13; padding: 18px; border-radius: 4px; font-family: monospace; font-size: 12px; text-align: left; margin-top: 25px; border: 1px solid rgba(255,255,255,0.05); }}
            .uuid {{ color: #00f2fe; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>KALKI SECURITY MITIGATION BLOCK ACTIVE</h1>
            <p>Your request was intercepted and dropped because it matched active threat signature profiles for <strong>{category}</strong>.</p>
            <div class="details">
                <div>Incident Reference ID: <span class="uuid">{incident_id}</span></div>
                <div>Origin Node IP: {client_ip}</div>
                <div>Scrubbing Posture: ACTIVE_BLOCK</div>
                <div>Timestamp Context: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
            </div>
        </div>
    </body>
    </html>
    """

async def waf_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/v1/") or request.url.path in ["/", "/dashboard", "/kalki_waf_logo.png"] or request.url.path.endswith("kalki_waf_logo.png"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    target_uri = str(request.url.path)
    query_params = str(request.url.query)
    body_payload = b""
    if request.method in ["POST", "PUT", "PATCH"]:
        body_payload = await request.body()
    inspectable_string = f"{query_params} {body_payload.decode('utf-8', errors='ignore')}"

    detected_threat = None
    matched_rule = None
    if not check_rate_limit(client_ip):
        detected_threat = "Anomalous"
        inspectable_string = "RATE_LIMIT_EXCEEDED"

    if not detected_threat:
        for rule in ACTIVE_RULES_CACHE:
            if rule['compiled_regex'].search(inspectable_string):
                detected_threat = rule['category']
                matched_rule = rule
                break

    if detected_threat:
        incident_id = str(uuid.uuid4())
        action = "Flagged" if GLOBAL_POSTURE == "Monitor Only" else "Blocked"
        event_log = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow(),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": inspectable_string[:500],
            "threat_category": detected_threat,
            "mitigation_action": action
        }
        if matched_rule:
            await run_in_threadpool(execute_db, "UPDATE rules SET blocks_count = blocks_count + 1 WHERE rule_id = %s", (matched_rule['rule_id'],))
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, event_log)
        if action == "Blocked":
            return HTMLResponse(content=generate_block_page(incident_id, client_ip, detected_threat), status_code=403, background=bg_tasks)

    upstream_request_url = f"{UPSTREAM_SERVER_URL}{target_uri}"
    if query_params:
        upstream_request_url += f"?{query_params}"
    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)
    if detected_threat and GLOBAL_POSTURE == "Monitor Only":
        proxy_headers["X-WAF-Flagged"] = "True"
        proxy_headers["X-WAF-Threat-Category"] = detected_threat

    bg_tasks = BackgroundTasks()
    if detected_threat:
        bg_tasks.add_task(log_incident_to_db, event_log)
    try:
        proxy_response = await http_client.request(
            method=request.method,
            url=upstream_request_url,
            headers=proxy_headers,
            content=body_payload if body_payload else None,
            cookies=request.cookies,
            timeout=10.0
        )
        response_headers = dict(proxy_response.headers)
        for h in ["content-encoding", "transfer-encoding", "content-length"]:
            response_headers.pop(h, None)
        return Response(content=proxy_response.content, status_code=proxy_response.status_code, headers=response_headers, background=bg_tasks if detected_threat else None)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream Server Unreachable: {exc}")
