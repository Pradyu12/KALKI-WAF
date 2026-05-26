from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

REQUEST_COUNT = Counter("waf_requests_total", "Total requests processed", ["method", "path", "status"])
BLOCKED_COUNT = Counter("waf_blocked_total", "Total blocked requests", ["category"])
REQUEST_DURATION = Histogram("waf_request_duration_seconds", "Request latency")
ACTIVE_CONNECTIONS = Gauge("waf_active_connections", "Current active connections")
UPSTREAM_TIMEOUTS = Counter("waf_upstream_timeouts_total", "Upstream request timeouts")


async def metrics_endpoint():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
