"""Shared helpers for the telemetry Flask application.

Provides authentication, pagination, and audit logging utilities used
across all route blueprints.
"""

import functools
import hmac
import logging
import os
from typing import Any

from flask import jsonify, request as flask_request

from database import get_connection, insert_audit_log
from oauth import get_current_user


def _get_telemetry_api_key() -> str:
    return os.environ.get("TELEMETRY_API_KEY", "")


def _is_authenticated() -> bool:
    """Check whether the current request supplies a valid API key.

    Returns ``True`` when ``TELEMETRY_API_KEY`` is unset (no auth required)
    or when the caller provides a matching key via ``X-API-Key`` or
    ``Authorization: Bearer`` header.
    """
    expected = _get_telemetry_api_key()
    if not expected:
        return True
    provided = flask_request.headers.get("X-API-Key", "")
    if not provided:
        auth = flask_request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            provided = auth[7:]
    return bool(provided) and hmac.compare_digest(provided, expected)


def require_api_key(fn):
    """Decorator that gates mutating endpoints behind TELEMETRY_API_KEY.

    When the key is unset or empty the endpoint is accessible without
    authentication (backwards-compatible for local development).  When
    the key IS set, callers must supply it via an ``X-API-Key`` header
    or an ``Authorization: Bearer <key>`` header.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


def _get_audit_user() -> str:
    user = get_current_user()
    if user:
        return user.get("login", "unknown")
    if _is_authenticated():
        return "api-key"
    return "anonymous"


def _audit(
    action: str,
    resource: str = "",
    details: str = "",
    conn: "sqlite3.Connection | None" = None,
) -> None:
    try:
        own_conn = conn is None
        if own_conn:
            conn = get_connection()
        try:
            insert_audit_log(conn, _get_audit_user(), action, resource, details)
        finally:
            if own_conn:
                conn.close()
    except Exception:
        logging.getLogger(__name__).warning("audit log write failed: action=%s", action, exc_info=True)


def _paginate(items: list[dict[str, Any]], page: int, per_page: int) -> dict[str, Any]:
    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    return {
        "items": items[start:end],
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


def _get_pagination() -> tuple[int, int]:
    page = max(1, int(flask_request.args.get("page", 1)))
    per_page = min(200, max(1, int(flask_request.args.get("per_page", 50))))
    return page, per_page
