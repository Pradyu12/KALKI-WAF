from fastapi import Request, Response

from waf.config import DLP_ENABLED
from waf.security.dlp import scan_for_dlp


async def inspect_response_body(request: Request, call_next):
    response: Response = await call_next(request)

    if not DLP_ENABLED:
        return response

    # Only scan text-based responses
    content_type = response.headers.get("content-type", "").lower()
    if not any(t in content_type for t in ("text/", "json", "xml", "javascript")):
        return response

    # Read response body
    body = b""
    async for chunk in response.body_iterator:
        body += chunk

    if not body:
        return Response(
            content=b"",
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

    findings = scan_for_dlp(body)
    if not findings:
        return Response(
            content=body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

    # Log DLP hits
    import json

    from waf.api.routes import log_audit
    from waf.db import execute_db

    for finding in findings:
        execute_db(
            "INSERT INTO siem_alerts (rule_id, rule_name, severity, source, description, raw_data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                finding["dlp_id"],
                finding["name"],
                finding["severity"],
                request.client.host if request.client else "unknown",
                f"DLP: {finding['name']} in response to {request.url.path}",
                json.dumps({"path": str(request.url.path), "dlp_id": finding["dlp_id"]}),
            ),
        )

    log_audit(
        "dlp_detected",
        "response",
        str(request.url.path),
        details=f"DLP triggered: {', '.join(f['name'] for f in findings)}",
        ip_address=request.client.host if request.client else "",
    )

    # In strict mode, block the response (return sanitized version)
    if any(f["severity"] == "critical" for f in findings):
        return Response(
            content=b"Response blocked by KALKI DLP: sensitive content detected",
            status_code=403,
            headers={"X-DLP-Blocked": "true", "X-DLP-Findings": ",".join(f["dlp_id"] for f in findings)},
        )

    # For non-critical findings, pass through with header flag
    header_dict = dict(response.headers)
    header_dict["X-DLP-Flagged"] = ",".join(f["dlp_id"] for f in findings)
    return Response(
        content=body,
        status_code=response.status_code,
        headers=header_dict,
        media_type=response.media_type,
    )
