import json
import os

import requests

from config import DEVIN_API_BASE, RUNS_DIR, devin_headers as _devin_headers


def poll_devin_sessions(sessions: list[dict], api_key: str = "") -> list[dict]:
    if not api_key:
        api_key = os.environ.get("DEVIN_API_KEY", "")
    if not api_key:
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
                headers=_devin_headers(api_key),
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
        except requests.RequestException:
            pass
        updated.append(s)
    return updated


def save_session_updates(sessions: list[dict]) -> bool:
    run_sessions: dict[str, list[dict]] = {}
    for s in sessions:
        label = s.get("run_label", "")
        if label not in run_sessions:
            run_sessions[label] = []
        run_sessions[label].append(s)

    any_written = False
    for fp in RUNS_DIR.glob("*.json"):
        try:
            with open(fp) as f:
                run_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        label = run_data.get("run_label", "")
        if label not in run_sessions:
            continue

        updated_map = {s["session_id"]: s for s in run_sessions[label] if s.get("session_id")}
        changed = False
        for s in run_data.get("sessions", []):
            sid = s.get("session_id", "")
            if sid in updated_map:
                new = updated_map[sid]
                if s.get("status") != new.get("status") or s.get("pr_url") != new.get("pr_url"):
                    s["status"] = new.get("status", s.get("status"))
                    if new.get("pr_url"):
                        s["pr_url"] = new["pr_url"]
                    changed = True
        if changed:
            with open(fp, "w") as f:
                json.dump(run_data, f, indent=2)
            any_written = True
    return any_written
