from fastapi import Request, Response

from waf.config import SECURITY_HEADERS


async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response
