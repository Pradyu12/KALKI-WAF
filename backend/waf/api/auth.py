import os
import sys
import uuid

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_ADMIN_API_KEY: str | None = None
_security = HTTPBearer(auto_error=False)


def _load_key():
    global _ADMIN_API_KEY
    key = os.environ.get("ADMIN_API_KEY")
    if key:
        _ADMIN_API_KEY = key
    else:
        _ADMIN_API_KEY = str(uuid.uuid4())
        print(f"[WARN] No ADMIN_API_KEY set. Generated temporary key: {_ADMIN_API_KEY}", file=sys.stderr)
        print("[WARN] Set ADMIN_API_KEY in your environment for a persistent key.", file=sys.stderr)


_load_key()


async def verify_admin_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> str | None:
    x_api_key = request.headers.get("X-API-Key", "")
    if credentials:
        x_api_key = credentials.credentials
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if x_api_key != _ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key
