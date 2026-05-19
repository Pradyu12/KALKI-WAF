"""
Simple upstream application for local WAF testing.
The WAF proxies clean traffic to this service.
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="Upstream Test App")


@app.get("/")
async def root():
    return JSONResponse({"message": "Hello from upstream! Traffic passed through WAF successfully."})


@app.get("/health")
async def health():
    return JSONResponse({"status": "healthy", "service": "upstream"})


@app.get("/api/data")
async def data():
    return JSONResponse({"data": [1, 2, 3, 4, 5], "source": "upstream_db"})


@app.post("/login")
async def login(body: dict = None):
    return JSONResponse({"result": "authenticated", "user": body.get("username", "unknown")})
