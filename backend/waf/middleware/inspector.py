import asyncio
import json
import time
import uuid
from datetime import UTC, datetime
from urllib.parse import unquote

import httpx
from fastapi import BackgroundTasks, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse

from waf import state
from waf.config import MAX_BODY_BYTES, UPSTREAM_SERVER_URL
from waf.core.block_page import generate_block_page
from waf.core.metrics import (
    ACTIVE_CONNECTIONS,
    BLOCKED_COUNT,
    REQUEST_COUNT,
    REQUEST_DURATION,
    UPSTREAM_TIMEOUTS,
)
from waf.core.webhooks import send_alert
from waf.core.websocket import broadcast_incident as ws_broadcast
from waf.middleware import rate_limiter
from waf.middleware.circuit_breaker import circuit_breaker
from waf.security import geoip
from waf.security.graphql import check_graphql_depth

http_client = httpx.AsyncClient()


async def read_limited_body(request: Request, max_bytes: int) -> bytes:
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_bytes:
            break
    return body


def log_incident_to_db(event_data: dict):
    from waf.db import execute_db

    query = """
        INSERT INTO security_events
        (incident_id, timestamp, source_ip, user_agent, target_uri, malicious_payload, threat_category, mitigation_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """  # noqa: E501
    ts = event_data["timestamp"]
    if isinstance(ts, datetime):
        ts = ts.strftime("%Y-%m-%d %H:%M:%S")
    args = (
        event_data["incident_id"],
        ts,
        event_data["source_ip"],
        event_data["user_agent"],
        event_data["target_uri"],
        event_data["malicious_payload"],
        event_data["threat_category"],
        event_data["mitigation_action"],
    )
    success = execute_db(query, args)
    if not success:
        print("[CRITICAL] Database Persistence Failure inside log_incident_to_db")


async def count_request(request: Request, call_next):
    state._request_count += 1
    response = await call_next(request)
    return response


async def inspect_and_proxy_traffic(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    target_uri = str(request.url.path)

    start_time = time.time()
    ACTIVE_CONNECTIONS.inc()

    if await geoip.check_country_block(client_ip):
        blocked_country = geoip.get_country_code(client_ip)
        incident_id = str(uuid.uuid4())
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(
            log_incident_to_db,
            {
                "incident_id": incident_id,
                "timestamp": datetime.now(UTC),
                "source_ip": client_ip,
                "user_agent": user_agent,
                "target_uri": target_uri,
                "malicious_payload": f"GEO_BLOCKED:{blocked_country}",
                "threat_category": "GeoBlock",
                "mitigation_action": "Blocked",
            },
        )
        html_payload = generate_block_page(incident_id, client_ip, "GeoBlock")
        return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

    if not await rate_limiter.check_rate_limit(client_ip):
        incident_id = str(uuid.uuid4())
        BLOCKED_COUNT.labels(category="rate_limit").inc()
        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(
            log_incident_to_db,
            {
                "incident_id": incident_id,
                "timestamp": datetime.now(UTC),
                "source_ip": client_ip,
                "user_agent": user_agent,
                "target_uri": target_uri,
                "malicious_payload": "RATE_LIMIT_EXCEEDED",
                "threat_category": "Anomalous",
                "mitigation_action": "Blocked",
            },
        )
        html_payload = generate_block_page(incident_id, client_ip, "Anomalous")
        return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

    if request.url.path.startswith("/api/v1/") or request.url.path in [
        "/", "/dashboard", "/earth.jpg", "/kalki_waf_logo.png", "/health", "/readyz", "/metrics"
    ]:
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status=str(response.status_code)).inc()
            ACTIVE_CONNECTIONS.dec()
            return response
        except Exception as e:
            ACTIVE_CONNECTIONS.dec()
            raise e

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type and request.method == "POST":
        try:
            body = await request.body()
            body_str = body.decode("utf-8", errors="ignore")
            json_body = json.loads(body_str)
            if "query" in json_body:
                if not check_graphql_depth(json_body["query"]):
                    incident_id = str(uuid.uuid4())
                    bg_tasks = BackgroundTasks()
                    bg_tasks.add_task(
                        log_incident_to_db,
                        {
                            "incident_id": incident_id,
                            "timestamp": datetime.now(UTC),
                            "source_ip": client_ip,
                            "user_agent": user_agent,
                            "target_uri": target_uri,
                            "malicious_payload": "GRAPHQL_DEPTH_EXCEEDED",
                            "threat_category": "GraphQL",
                            "mitigation_action": "Blocked",
                        },
                    )
                    html_payload = generate_block_page(incident_id, client_ip, "GraphQL")
                    return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)
                request._body = body
        except Exception:
            pass

    query_params = unquote(str(request.url.query), encoding="utf-8", errors="replace")
    body_payload = b""

    if request.method in ["POST", "PUT", "PATCH"]:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_BYTES:
            incident_id = str(uuid.uuid4())
            bg_tasks = BackgroundTasks()
            bg_tasks.add_task(
                log_incident_to_db,
                {
                    "incident_id": incident_id,
                    "timestamp": datetime.now(UTC),
                    "source_ip": client_ip,
                    "user_agent": user_agent,
                    "target_uri": target_uri,
                    "malicious_payload": f"REQUEST_BODY_TOO_LARGE:{content_length}",
                    "threat_category": "Anomalous",
                    "mitigation_action": "Blocked",
                },
            )
            return JSONResponse(
                {"error": "Request body too large", "max_bytes": MAX_BODY_BYTES}, status_code=413, background=bg_tasks
            )  # noqa: E501

        body_payload = await read_limited_body(request, MAX_BODY_BYTES)
        if len(body_payload) > MAX_BODY_BYTES:
            incident_id = str(uuid.uuid4())
            bg_tasks = BackgroundTasks()
            bg_tasks.add_task(
                log_incident_to_db,
                {
                    "incident_id": incident_id,
                    "timestamp": datetime.now(UTC),
                    "source_ip": client_ip,
                    "user_agent": user_agent,
                    "target_uri": target_uri,
                    "malicious_payload": f"REQUEST_BODY_TOO_LARGE:{len(body_payload)}",
                    "threat_category": "Anomalous",
                    "mitigation_action": "Blocked",
                },
            )
            return JSONResponse({"error": "Request body too large"}, status_code=413, background=bg_tasks)

    inspectable_string = f"{query_params} {body_payload.decode('utf-8', errors='ignore')}"

    detected_threat = None
    matched_rule = None

    for rule in state.ACTIVE_RULES_CACHE:
        try:
            if rule["compiled_regex"].search(inspectable_string):
                detected_threat = rule["category"]
                matched_rule = rule
                break
        except Exception as e:
            print(f"[ERROR] Regex matching error on rule {rule['identifier']}: {e}")

    if detected_threat:
        incident_id = str(uuid.uuid4())
        BLOCKED_COUNT.labels(category=detected_threat).inc()

        action = "Flagged" if state.GLOBAL_POSTURE == "Monitor Only" else "Blocked"

        event_log = {
            "incident_id": incident_id,
            "timestamp": datetime.now(UTC),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": inspectable_string[:500],
            "threat_category": detected_threat,
            "mitigation_action": action,
        }

        incident_payload = {
            "incident_id": incident_id,
            "source_ip": client_ip,
            "threat_category": detected_threat,
            "action": action,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        await ws_broadcast(incident_payload)
        if action == "Blocked":
            asyncio.ensure_future(send_alert(incident_payload))

        if matched_rule:
            rule_id = matched_rule["rule_id"]
            from waf.db import execute_db

            await run_in_threadpool(
                execute_db, "UPDATE rules SET blocks_count = blocks_count + 1 WHERE rule_id = ?", (rule_id,)
            )  # noqa: E501

        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, event_log)

        if action == "Blocked":
            html_payload = generate_block_page(incident_id, client_ip, detected_threat)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="403").inc()
            ACTIVE_CONNECTIONS.dec()
            return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

    upstream_request_url = f"{UPSTREAM_SERVER_URL}{target_uri}"
    if query_params:
        upstream_request_url += f"?{query_params}"

    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)

    if detected_threat and state.GLOBAL_POSTURE == "Monitor Only":
        proxy_headers["X-WAF-Flagged"] = "True"
        proxy_headers["X-WAF-Threat-Category"] = detected_threat

    bg_tasks = BackgroundTasks()
    if detected_threat:
        bg_tasks.add_task(log_incident_to_db, event_log)

    try:
        proxy_response = await circuit_breaker.call(
            http_client.request,
            method=request.method,
            url=upstream_request_url,
            headers=proxy_headers,
            content=body_payload if body_payload else None,
            timeout=10.0,
        )

        response_headers = dict(proxy_response.headers)
        response_headers.pop("content-encoding", None)
        response_headers.pop("transfer-encoding", None)
        response_headers.pop("content-length", None)

        duration = time.time() - start_time
        REQUEST_DURATION.observe(duration)
        REQUEST_COUNT.labels(method=request.method, path=target_uri, status=str(proxy_response.status_code)).inc()
        ACTIVE_CONNECTIONS.dec()

        return Response(
            content=proxy_response.content,
            status_code=proxy_response.status_code,
            headers=response_headers,
            background=bg_tasks if detected_threat else None,
        )
    except HTTPException:
        ACTIVE_CONNECTIONS.dec()
        raise
    except httpx.RequestError as exc:
        UPSTREAM_TIMEOUTS.inc()
        ACTIVE_CONNECTIONS.dec()
        import sys
        import traceback as _tb

        _tb.print_exc(file=sys.stderr)
        raise HTTPException(status_code=502, detail=f"Upstream Server Unreachable: {exc}") from exc
