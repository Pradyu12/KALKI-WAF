import os
import uuid

from fastapi import Header, HTTPException

_ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
if not _ADMIN_API_KEY:
    _ADMIN_API_KEY = str(uuid.uuid4())
    print(f"[WARN] No ADMIN_API_KEY set. Generated temporary key: {_ADMIN_API_KEY}")
    print("[WARN] Set ADMIN_API_KEY in your environment for a persistent key.")


async def verify_admin_key(x_api_key: str = Header(default=None)) -> str | None:
    if x_api_key != _ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return x_api_key
