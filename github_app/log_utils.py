"""Utilities for safe logging of user-provided values."""

from __future__ import annotations

import re

_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


def sanitize_log(value: object) -> str:
    """Sanitize a value for safe inclusion in log messages.

    Strips newlines and other ASCII control characters that could be
    used to forge log entries (CWE-117 / py/log-injection).
    Returns a new plain string that is safe for logging.
    """
    text = str(value)
    cleaned = _CONTROL_CHAR_RE.sub("", text)
    return "".join(cleaned)
