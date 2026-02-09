"""Centralised structured logging configuration for the pipeline.

Provides a JSON-lines formatter so that every log record is emitted as a
single JSON object.  This enables log aggregation in CloudWatch, Datadog,
Splunk, and similar systems without custom parsing rules.

Usage
-----
::

    from logging_config import setup_logging

    logger = setup_logging(__name__)
    logger.info("scan started", extra={"repo": "owner/repo"})
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        for key in ("repo", "run_id", "batch_id", "session_id", "file"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        return json.dumps(log_entry, default=str)


class _StderrHandler(logging.Handler):
    """Handler that resolves ``sys.stderr`` at emit time.

    Unlike ``StreamHandler(sys.stderr)`` which captures the reference once,
    this handler always uses the *current* ``sys.stderr`` so that pytest's
    ``capsys`` / ``capfd`` fixtures can intercept log output.
    """

    terminator = "\n"

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            sys.stderr.write(msg + self.terminator)
            sys.stderr.flush()
        except Exception:
            self.handleError(record)


def setup_logging(
    name: str = "",
    level: str | None = None,
) -> logging.Logger:
    """Configure and return a logger with JSON-lines output on *stderr*.

    Parameters
    ----------
    name : str
        Logger name, typically ``__name__`` of the calling module.
    level : str | None
        Override log level (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        Defaults to the ``LOG_LEVEL`` environment variable or ``INFO``.
    """
    resolved_level = (level or os.environ.get("LOG_LEVEL", "INFO")).upper()

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, resolved_level, logging.INFO))

    handler = _StderrHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    logger.propagate = False

    return logger
