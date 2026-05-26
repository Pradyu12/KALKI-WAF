import asyncio
import os
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from waf.api.routes import router
from waf.core.telemetry import start_metrics_sampler
from waf.db import init_db
from waf.middleware.inspector import count_request, http_client, inspect_and_proxy_traffic
from waf.middleware.rate_limiter import get_redis_client, redis_client
from waf.rules.engine import reload_global_posture, reload_rules_cache
from waf.security.geoip import init_geoip

_metrics_task: asyncio.Task = None
_otel_started = False


def _start_otel():
    global _otel_started
    if _otel_started or os.environ.get("OTEL_SDK_DISABLED"):
        return
    _otel_started = True

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://datadog-agent:4317")
    resource = Resource(attributes={"service.name": "kalki-waf"})
    provider = TracerProvider(resource=resource)
    if otlp_endpoint:
        try:
            exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            print(f"[INFO] OpenTelemetry OTLP exporter configured -> {otlp_endpoint}")
        except Exception as err:
            print(f"[WARN] Failed to configure OTLP exporter: {err}")

    current_provider = trace.get_tracer_provider()
    if not isinstance(current_provider, TracerProvider):
        trace.set_tracer_provider(provider)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _metrics_task
    _start_otel()
    with suppress(Exception):
        FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())
    await init_geoip()
    await get_redis_client()
    init_db()
    reload_rules_cache()
    reload_global_posture()
    _metrics_task = start_metrics_sampler()
    yield
    if _metrics_task:
        _metrics_task.cancel()
    if redis_client:
        await redis_client.close()
    await http_client.aclose()


app = FastAPI(title="Kalki WAF Core Engine", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(count_request)
app.middleware("http")(inspect_and_proxy_traffic)
app.include_router(router)

if __name__ == "__main__":
    import subprocess

    try:
        result = subprocess.run(["fuser", "-k", "8000/tcp"], capture_output=True)
        if result.returncode == 0:
            print("[INFO] Freed port 8000")
    except FileNotFoundError:
        try:
            pid = subprocess.check_output(
                ["lsof", "-ti", ":8000"], stderr=subprocess.DEVNULL
            ).decode().strip()
            if pid:
                for p in pid.split():
                    os.kill(int(p), 9)
                print(f"[INFO] Killed old process(es) on port 8000: {pid}")
        except Exception:
            pass

    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
