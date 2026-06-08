"""CSRF token enforcement middleware (opt-in).

Requires a valid ``X-CSRF-Token`` header on all POST/PUT/PATCH/DELETE
requests to non-API paths.  Tokens are HMAC-signed with the client origin
and expire after a configurable TTL.
"""

import base64
import hashlib
import hmac
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from waf.config import CSRF_ENABLED, CSRF_SECRET

_CSRF_TTL = 3600  # 1 hour


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _unb64(s: str) -> str:
    # Pad to multiple of 4
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s).decode()


def _generate_token(origin: str) -> str:
    ts = str(int(time.time()))
    origin_b64 = _b64(origin)
    payload = f"{ts}.{origin_b64}"
    sig = hmac.new(CSRF_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{ts}.{origin_b64}.{sig}"


def _validate_token(token: str, origin: str) -> bool:
    try:
        parts = token.split(".")
        if len(parts) < 3:
            return False
        ts_str = parts[0]
        origin_b64 = ".".join(parts[1:-1])
        sig = parts[-1]
        if not ts_str.isdigit():
            return False
        ts = int(ts_str)
        if time.time() - ts > _CSRF_TTL:
            return False
        token_origin = _unb64(origin_b64)
        expected_sig = hmac.new(
            CSRF_SECRET.encode(), f"{ts}.{_b64(token_origin)}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(sig, expected_sig) and token_origin == origin
    except (ValueError, IndexError, Exception):
        return False


def generate_csrf_token(origin: str = "app") -> str:
    return _generate_token(origin)


_SKIP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


async def csrf_check(request: Request, call_next):
    response = await call_next(request)
    if not CSRF_ENABLED:
        return response

    if request.method.upper() in _SKIP_METHODS:
        return response

    # Skip API endpoints
    if str(request.url.path).startswith("/api/"):
        return response

    # Skip bypass paths
    if str(request.url.path) in frozenset({"/dashboard", "/health", "/readyz", "/metrics", "/"}):
        return response

    token = request.headers.get("X-CSRF-Token", "")
    origin = request.headers.get("Origin", request.headers.get("Referer", "app"))

    if not token:
        return JSONResponse(
            status_code=403,
            content={"error": "CSRF token required", "detail": "Missing X-CSRF-Token header"},
        )

    if not _validate_token(token, origin):
        return JSONResponse(
            status_code=403,
            content={"error": "CSRF validation failed", "detail": "Invalid or expired token"},
        )

    return response
