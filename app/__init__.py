from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .database import init_db
from .middleware import reload_rules_cache, reload_global_posture, waf_middleware, http_client
from .routes import router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    reload_rules_cache()
    reload_global_posture()
    yield
    await http_client.aclose()

def create_app() -> FastAPI:
    app = FastAPI(title="Kalki WAF Core Engine", version="1.1.0", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def waf_interceptor(request: Request, call_next):
        return await waf_middleware(request, call_next)

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "type": "INTERNAL_SERVER_ERROR",
                "message": "A critical backend anomaly has been detected.",
                "detail": str(exc)
            }
        )

    app.include_router(router)

    return app
