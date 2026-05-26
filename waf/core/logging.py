import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

LOG_FORMAT = os.getenv("LOG_FORMAT", "json")
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")


def log(level: str, message: str, **extra: Any) -> None:
    if LOG_FORMAT == "json":
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level.upper(),
            "message": message,
            "service": "kalki-waf",
        }
        record.update(extra)
        print(json.dumps(record), file=sys.stderr, flush=True)
    else:
        extra_str = " ".join(f"{k}={v}" for k, v in extra.items())
        print(f"[{level.upper()}] {message} {extra_str}".strip(), file=sys.stderr, flush=True)


def info(message: str, **extra: Any) -> None:
    log("info", message, **extra)


def warn(message: str, **extra: Any) -> None:
    log("warn", message, **extra)


def error(message: str, **extra: Any) -> None:
    log("error", message, **extra)


def critical(message: str, **extra: Any) -> None:
    log("critical", message, **extra)
