"""Structured logging setup (level via env, correlation-id friendly)."""

from __future__ import annotations

import logging
import os
import sys

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"


class RequestIdFilter(logging.Filter):
    """Injects a per-request correlation id placeholder into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()
    if root.handlers:  # already configured (e.g. under uvicorn/pytest)
        root.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("uvicorn.access").setLevel(level)
    # Noisy third-party loggers
    logging.getLogger("paho-mqtt").setLevel(logging.WARNING)
