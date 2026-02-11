import json
import logging
import os
import sqlite3

import requests

from config import DEVIN_API_BASE, devin_headers

try:
    from devin_api import TERMINAL_STATUSES, clean_session_id
except ImportError:
    from scripts.devin_api import TERMINAL_STATUSES, clean_session_id

logger = logging.getLogger(__name__)


def _extract_structured_output(data: dict) -> dict:
    so = data.get("structured_output")
    if isinstance(so, dict):
        return so
    return {}


def _extract_pr_url(data: dict, so: dict) -> str:
    pr_url = so.get("pull_request_url", "")
    if not pr_url:
        res = data.get("result")
        if isinstance(res, dict):
            pr_url = res.get("pull_request_url", "")
    if not pr_url:
        pr_info = data.get("pull_request")
        if isinstance(pr_info, dict):
            pr_url = pr_info.get("url", "") or pr_info.get("html_url", "")
        elif isinstance(pr_info, str):
            pr_url = pr_info
    return pr_url


def poll_devin_sessions_db(
    conn: sqlite3.Connection, sessions: list[dict]
) -> list[dict]:
    from database import update_session

    key = os.environ.get("DEVIN_API_KEY", "")
    if not key:
        logger.warning("DEVIN_API_KEY not set, skipping session polling")
        return sessions

    updated: list[dict] = []
    errors: list[dict] = []
    polled = 0
    skipped_terminal = 0
    for s in sessions:
        sid = s.get("session_id", "")
        if not sid or sid == "dry-run":
            updated.append(s)
            continue
        status = s.get("status", "unknown")
        if status in TERMINAL_STATUSES:
            skipped_terminal += 1
            updated.append(s)
            continue
        try:
            clean_sid = clean_session_id(sid)
            resp = requests.get(
                f"{DEVIN_API_BASE}/sessions/{clean_sid}",
                headers=devin_headers(),
                timeout=15,
            )
            polled += 1
            if resp.status_code == 200:
                data = resp.json()
                status_str = str(
                    data.get("status_enum")
                    or data.get("status")
                    or "unknown"
                ).lower()
                if isinstance(status_str, dict):
                    status_str = status_str.get("status", "unknown")
                s["status"] = status_str

                so = _extract_structured_output(data)
                pr_url = _extract_pr_url(data, so)
                if pr_url:
                    s["pr_url"] = pr_url
                if so:
                    s["structured_output"] = so

                so_json = json.dumps(so) if so else ""
                update_session(
                    conn, sid,
                    status=status_str,
                    pr_url=pr_url,
                    structured_output=so_json,
                )
            else:
                logger.warning(
                    "Devin API returned %d for session %s: %s",
                    resp.status_code, sid, resp.text[:200],
                )
                errors.append({"session_id": sid, "error": f"HTTP {resp.status_code}"})
        except requests.RequestException as exc:
            logger.error("Failed to poll session %s: %s", sid, exc)
            errors.append({"session_id": sid, "error": str(exc)})
        updated.append(s)

    logger.info(
        "Polling complete: %d polled, %d skipped (terminal), %d errors",
        polled, skipped_terminal, len(errors),
    )

    return updated, {"polled": polled, "skipped_terminal": skipped_terminal, "errors": errors}
