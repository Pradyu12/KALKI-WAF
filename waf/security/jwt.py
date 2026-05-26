import jwt as _pyjwt
from fastapi import Request

from waf.config import JWT_SECRET


def validate_jwt_token(request: Request):
    if not JWT_SECRET:
        return None
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    if not token:
        return None
    try:
        payload = _pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except Exception:
        return None
