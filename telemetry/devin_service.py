import os
import sqlite3

import requests

from config import DEVIN_API_BASE, devin_headers


def poll_devin_sessions_db(
    conn: sqlite3.Connection, sessions: list[dict]
) -> list[dict]:
    from database import update_session

    key = os.environ.get("DEVIN_API_KEY", "")
    if not key:
        return sessions

    updated = []
    for s in sessions:
        sid = s.get("session_id", "")
        if not sid or sid == "dry-run":
            updated.append(s)
            continue
        try:
            clean_sid = sid.replace("devin-", "") if sid.startswith("devin-") else sid
            resp = requests.get(
                f"{DEVIN_API_BASE}/sessions/{clean_sid}",
                headers=devin_headers(),
                timeout=15,
            )
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
                pr_url = ""
                so = data.get("structured_output")
                if isinstance(so, dict):
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
                if pr_url:
                    s["pr_url"] = pr_url
                update_session(conn, sid, status=status_str, pr_url=pr_url)
        except requests.RequestException:
            pass
        updated.append(s)
    return updated
