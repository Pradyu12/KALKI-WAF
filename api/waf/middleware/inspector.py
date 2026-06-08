import asyncio
import json
import time
import uuid
from datetime import datetime

try:
    from datetime import UTC
except ImportError:
    UTC = UTC
from urllib.parse import unquote

import httpx
from fastapi import BackgroundTasks, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse

from waf import state
from waf.config import DLP_ENABLED, MAX_BODY_BYTES, TRUSTED_IPS, UPSTREAM_SERVER_URL
from waf.core.block_page import generate_block_page
from waf.core.metrics import (
    ACTIVE_CONNECTIONS,
    BLOCKED_COUNT,
    REQUEST_COUNT,
    REQUEST_DURATION,
    RULE_HITS,
    UPSTREAM_TIMEOUTS,
)
from waf.core.telemetry import _telemetry_lock
from waf.core.webhooks import send_alert
from waf.core.websocket import broadcast_incident as ws_broadcast
from waf.middleware import rate_limiter
from waf.middleware.circuit_breaker import circuit_breaker
from waf.rules.automaton import AUTOMATON
from waf.security import geoip
from waf.security.graphql import check_graphql_depth

http_client = httpx.AsyncClient(http2=True)

_BLOCK_THRESHOLD = 5  # auto-blacklist if N blocks
_BLOCK_WINDOW = 60  # within this many seconds
_AUTO_BLACKLIST_HOURS = 1


def _run_anomaly_check(ip: str, headers: dict, ua: str):
    try:
        from waf.core.anomaly import check_anomaly

        score = check_anomaly(ip, headers, ua)
        if score >= 0:
            pass  # anomaly already logged by check_anomaly; could log debug here
    except Exception:
        pass  # anomaly scoring is best-effort


import ipaddress


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is a private/local address that should never be auto-blacklisted."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _check_auto_blacklist(ip: str) -> bool:
    """Check if IP has exceeded block threshold and auto-blacklist if so."""
    if _is_private_ip(ip):
        return False
    if ip in TRUSTED_IPS:
        return False
    now = time.time()
    timestamps = state.AUTO_BLACKLIST_TRACKER.get(ip, [])
    timestamps = [t for t in timestamps if now - t < _BLOCK_WINDOW]
    timestamps.append(now)
    state.AUTO_BLACKLIST_TRACKER[ip] = timestamps
    if len(timestamps) >= _BLOCK_THRESHOLD:
        state.IP_BLACKLIST.add(ip)
        # Also persist to DB
        from datetime import UTC as _utc
        from datetime import datetime as _dt
        from datetime import timedelta

        _exp = (_dt.now(_utc) + timedelta(hours=_AUTO_BLACKLIST_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
        from waf.db import execute_db as _edb

        _edb(
            "INSERT OR REPLACE INTO ip_blacklist (ip_address, reason, created_by, expires_at) VALUES (?, ?, 'auto', ?)",
            (ip, f"Auto-blacklist: {_BLOCK_THRESHOLD} blocks in {_BLOCK_WINDOW}s", _exp),
        )
        return True
    return False


_BYPASS_PATHS = frozenset({"/", "/dashboard", "/earth.jpg", "/kalki_waf_logo.png", "/health", "/readyz", "/metrics"})


async def read_body_once(request: Request, max_bytes: int) -> bytes:
    if hasattr(request, "_consumed_body"):
        return request._consumed_body
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_bytes:
            break
    request._consumed_body = body
    request._body = body
    return body


def log_incident_to_db(event_data: dict):
    from waf.db import execute_db

    query = """
        INSERT INTO security_events
        (incident_id, timestamp, source_ip, user_agent, target_uri, malicious_payload, threat_category, mitigation_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
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
    try:
        success = execute_db(query, args)
        if not success:
            print("[CRITICAL] Database Persistence Failure inside log_incident_to_db")
    except Exception as e:
        print(f"[ERROR] Failed to log incident to database: {e}")


async def count_request(request: Request, call_next):
    async with _telemetry_lock:
        state._request_count += 1
    response = await call_next(request)
    return response


async def inspect_and_proxy_traffic(request: Request, call_next):
    raw_ip = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("x-forwarded-for", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else raw_ip
    user_agent = request.headers.get("user-agent", "Unknown")
    target_uri = str(request.url.path)

    start_time = time.time()
    ACTIVE_CONNECTIONS.inc()

    # Fire-and-forget anomaly scoring (non-blocking)
    asyncio.ensure_future(asyncio.to_thread(_run_anomaly_check, client_ip, dict(request.headers), user_agent))

    if client_ip in state.IP_BLACKLIST and not _is_private_ip(client_ip) and client_ip not in TRUSTED_IPS:
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
                "malicious_payload": f"BLACKLISTED_IP:{client_ip}",
                "threat_category": "GeoBlock",
                "mitigation_action": "Blocked",
            },
        )
        html_payload = generate_block_page(incident_id, client_ip, "Blacklisted")
        ACTIVE_CONNECTIONS.dec()
        return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

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
        ACTIVE_CONNECTIONS.dec()
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
        ACTIVE_CONNECTIONS.dec()
        return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

    if request.url.path.startswith("/api/v1/") or request.url.path in _BYPASS_PATHS:
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

    body = await read_body_once(request, MAX_BODY_BYTES)

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type and request.method == "POST":
        try:
            body_str = body.decode("utf-8", errors="ignore")
            json_body = json.loads(body_str)
            if "query" in json_body and not check_graphql_depth(json_body["query"]):
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
                ACTIVE_CONNECTIONS.dec()
                return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)
        except Exception:
            pass

    query_params = unquote(str(request.url.query), encoding="utf-8", errors="replace")

    if request.method in ["POST", "PUT", "PATCH"]:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl = int(content_length)
            except (ValueError, TypeError):
                cl = 0
            if cl > MAX_BODY_BYTES:
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
                ACTIVE_CONNECTIONS.dec()
                return JSONResponse(
                    {"error": "Request body too large", "max_bytes": MAX_BODY_BYTES},
                    status_code=413,
                    background=bg_tasks,
                )

    inspectable_string = f"{query_params} {body.decode('utf-8', errors='ignore')}"

    detected_threat = None
    matched_rule = None
    rule_action = "none"

    candidate_ids = AUTOMATON.find_candidates(inspectable_string) if AUTOMATON.is_built else set()
    for rule in state.ACTIVE_RULES_CACHE:
        if candidate_ids and rule["rule_id"] not in candidate_ids:
            continue
        try:
            if rule["compiled_regex"].search(inspectable_string):
                detected_threat = rule["category"]
                matched_rule = rule
                RULE_HITS.labels(rule_id=rule["rule_id"], category=rule["category"], action=rule["action"]).inc()
                break
        except Exception as e:
            print(f"[ERROR] Regex matching error on rule {rule['identifier']}: {e}")

    trace_id = str(uuid.uuid4())[:8]

    if detected_threat:
        incident_id = str(uuid.uuid4())
        BLOCKED_COUNT.labels(category=detected_threat).inc()

        rule_action = (matched_rule["action"] if matched_rule else "Block").strip().lower()
        # Normalize action names
        _action_normalize = {
            "drop & blacklist": "block & blacklist",
            "log payload only": "log only",
        }
        rule_action = _action_normalize.get(rule_action, rule_action)

        # Monitor Only overrides all actions — just flag and continue
        if state.GLOBAL_POSTURE == "Monitor Only":
            rule_action = "log only"

        event_log = {
            "incident_id": incident_id,
            "timestamp": datetime.now(UTC),
            "source_ip": client_ip,
            "user_agent": user_agent,
            "target_uri": target_uri,
            "malicious_payload": inspectable_string[:500],
            "threat_category": detected_threat,
            "mitigation_action": rule_action,
        }

        incident_payload = {
            "incident_id": incident_id,
            "source_ip": client_ip,
            "threat_category": detected_threat,
            "action": rule_action,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        await ws_broadcast(incident_payload)
        if rule_action in ("block", "drop", "block & blacklist"):
            asyncio.ensure_future(send_alert(incident_payload))

        if matched_rule:
            rule_id = matched_rule["rule_id"]
            from waf.db import execute_db

            await run_in_threadpool(
                execute_db, "UPDATE rules SET blocks_count = blocks_count + 1 WHERE rule_id = ?", (rule_id,)
            )

        bg_tasks = BackgroundTasks()
        bg_tasks.add_task(log_incident_to_db, event_log)

        # ── Per-rule action dispatch ──────────────────────────────────────

        # "drop" — minimal response, close connection
        if rule_action == "drop":
            _check_auto_blacklist(client_ip)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="403").inc()
            ACTIVE_CONNECTIONS.dec()
            return Response(status_code=403, headers={"Connection": "close"}, background=bg_tasks)

        # "block & blacklist" — block page + add to IP blacklist (persistent)
        if rule_action == "block & blacklist":
            if not _is_private_ip(client_ip) and client_ip not in TRUSTED_IPS:
                state.IP_BLACKLIST.add(client_ip)
                from datetime import timedelta

                _exp = (datetime.now(UTC) + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
                from waf.db import execute_db as _edb

                _edb(
                    "INSERT OR REPLACE INTO ip_blacklist (ip_address, reason, created_by, expires_at) VALUES (?, ?, 'rule', ?)",
                    (client_ip, f"Rule matched: {matched_rule['identifier'] if matched_rule else 'unknown'}", _exp),
                )
            html_payload = generate_block_page(incident_id, client_ip, detected_threat)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="403").inc()
            ACTIVE_CONNECTIONS.dec()
            return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

        # "block" — standard 403 block page
        if rule_action == "block":
            _check_auto_blacklist(client_ip)
            html_payload = generate_block_page(incident_id, client_ip, detected_threat)
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="403").inc()
            ACTIVE_CONNECTIONS.dec()
            return HTMLResponse(content=html_payload, status_code=403, background=bg_tasks)

        # "js challenge" — serve browser challenge page
        if rule_action == "js challenge":
            from waf.middleware.js_challenge import generate_challenge_page

            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="403").inc()
            ACTIVE_CONNECTIONS.dec()
            return generate_challenge_page(request, reason=detected_threat)

        # "rate limit" — apply per-rule rate limit then continue
        if rule_action == "rate limit" and not await rate_limiter.check_rate_limit(client_ip):
            _check_auto_blacklist(client_ip)
            html_payload = generate_block_page(incident_id, client_ip, f"RateLimited:{detected_threat}")
            duration = time.time() - start_time
            REQUEST_DURATION.observe(duration)
            REQUEST_COUNT.labels(method=request.method, path=target_uri, status="429").inc()
            ACTIVE_CONNECTIONS.dec()
            return HTMLResponse(content=html_payload, status_code=429, background=bg_tasks)

        # "log only" / "log payload only" — log and fall through to proxy
        # (already logged above; continue to proxy with flag header)

    upstream_request_url = f"{UPSTREAM_SERVER_URL}{target_uri}"
    if query_params:
        upstream_request_url += f"?{query_params}"

    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)

    if detected_threat and state.GLOBAL_POSTURE == "Monitor Only":
        proxy_headers["X-WAF-Flagged"] = "True"
        proxy_headers["X-WAF-Threat-Category"] = detected_threat

    if detected_threat and rule_action in ("log only", "log payload only", "rate limit"):
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
            content=body if body else None,
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

        # ── DLP response body scan ────────────────────────────────────────────
        if DLP_ENABLED and proxy_response.content:
            _ct = response_headers.get("content-type", "").lower()
            if any(_t in _ct for _t in ("text/", "json", "xml", "javascript")):
                from waf.security.dlp import scan_for_dlp as _scan_dlp

                _findings = _scan_dlp(proxy_response.content)
                if _findings:
                    for _f in _findings:
                        from waf.db import execute_db as _dlp_db

                        _dlp_db(
                            "INSERT INTO siem_alerts (rule_id, rule_name, severity, source, description, raw_data) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                _f["dlp_id"],
                                _f["name"],
                                _f["severity"],
                                client_ip,
                                f"DLP: {_f['name']} in {target_uri}",
                                f'{{"path":"{target_uri}","dlp_id":"{_f["dlp_id"]}"}}',
                            ),
                        )
                    if any(_f["severity"] == "critical" for _f in _findings):
                        return Response(
                            content=b"Response blocked by KALKI DLP",
                            status_code=403,
                            headers={"X-DLP-Blocked": "true"},
                        )
                    response_headers["X-DLP-Flagged"] = ",".join(_f["dlp_id"] for _f in _findings)

        response_headers["X-Kalki-Trace-Id"] = trace_id
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
        raise HTTPException(status_code=502, detail=f"Upstream Server Unreachable: {exc}") from exc
