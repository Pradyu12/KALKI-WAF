import asyncio
from typing import Any

LIVE_STATS: dict[str, float] = {
    "requests_per_second": 0.0,
    "cpu_percent": 0.0,
    "memory_mb": 0.0,
    "active_connections": 0,
}

ACTIVE_RULES_CACHE: list[dict[str, Any]] = []
GLOBAL_POSTURE: str = "Standard Posture"
IP_BLACKLIST: set[str] = set()
AUTO_BLACKLIST_TRACKER: dict[str, list[float]] = {}  # IP -> list of block timestamps

request_history: dict[str, list[float]] = {}

_metrics_task: asyncio.Task | None = None
_request_count: int = 0
