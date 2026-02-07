#!/usr/bin/env python3
"""Centralized telemetry server for CodeQL Devin Fixer.

Aggregates data from all action runs across every target repository into a
single dashboard.  Run data is stored as JSON files under ``telemetry/runs/``
in this repository -- each action run pushes one file via the GitHub Contents
API (see ``scripts/persist_telemetry.py``).

Endpoints
---------
GET  /                  Serve the dashboard UI.
GET  /api/runs          Return all run records.
GET  /api/sessions      Return all Devin sessions (aggregated from runs).
GET  /api/prs           Return PRs fetched from the GitHub API.
GET  /api/stats         Return aggregated statistics.
POST /api/poll          Poll Devin API for live session statuses.
POST /api/poll-prs      Poll GitHub API for PR statuses.
POST /api/refresh       Pull latest telemetry data from the repo.

Configuration is via environment variables or a ``.env`` file in this
directory:

GITHUB_TOKEN   PAT with ``repo`` scope (for GitHub API calls).
DEVIN_API_KEY  Devin API key (for polling session statuses).
ACTION_REPO    The repo where telemetry lives, e.g. ``marius-posa/codeql-devin-fixer``.

Start with::

    cd telemetry
    pip install -r requirements.txt
    python app.py
"""

import json
import os
import pathlib
import re
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

RUNS_DIR = pathlib.Path(__file__).parent / "runs"
DEVIN_API_BASE = "https://api.devin.ai/v1"


def _gh_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _devin_headers() -> dict:
    key = os.environ.get("DEVIN_API_KEY", "")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def load_runs() -> list[dict]:
    runs = []
    if not RUNS_DIR.is_dir():
        return runs
    for fp in sorted(RUNS_DIR.glob("*.json")):
        try:
            with open(fp) as f:
                data = json.load(f)
                data["_file"] = fp.name
                runs.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return runs


def aggregate_sessions(runs: list[dict]) -> list[dict]:
    sessions = []
    for run in runs:
        for s in run.get("sessions", []):
            sessions.append({
                "session_id": s.get("session_id", ""),
                "session_url": s.get("session_url", ""),
                "batch_id": s.get("batch_id"),
                "status": s.get("status", "unknown"),
                "issue_ids": s.get("issue_ids", []),
                "target_repo": run.get("target_repo", ""),
                "fork_url": run.get("fork_url", ""),
                "run_number": run.get("run_number"),
                "run_label": run.get("run_label", ""),
                "timestamp": run.get("timestamp", ""),
                "pr_url": s.get("pr_url", ""),
            })
    return sessions


def aggregate_stats(runs: list[dict], sessions: list[dict], prs: list[dict]) -> dict:
    repos = set()
    total_issues = 0
    severity_agg: dict[str, int] = {}
    category_agg: dict[str, int] = {}

    for run in runs:
        repo = run.get("target_repo", "")
        if repo:
            repos.add(repo)
        total_issues += run.get("issues_found", 0)
        for tier, count in run.get("severity_breakdown", {}).items():
            severity_agg[tier] = severity_agg.get(tier, 0) + count
        for cat, count in run.get("category_breakdown", {}).items():
            category_agg[cat] = category_agg.get(cat, 0) + count

    pr_merged = sum(1 for p in prs if p.get("merged", False))
    pr_open = sum(1 for p in prs if p.get("state") == "open")
    pr_closed = sum(1 for p in prs if p.get("state") == "closed" and not p.get("merged", False))

    sessions_created = len([s for s in sessions if s.get("session_id")])
    sessions_finished = len([s for s in sessions if s.get("status") == "finished"])
    sessions_with_pr = len([s for s in sessions if s.get("pr_url")])

    return {
        "repos_scanned": len(repos),
        "repo_list": sorted(repos),
        "total_runs": len(runs),
        "total_issues": total_issues,
        "sessions_created": sessions_created,
        "sessions_finished": sessions_finished,
        "sessions_with_pr": sessions_with_pr,
        "prs_total": len(prs),
        "prs_merged": pr_merged,
        "prs_open": pr_open,
        "prs_closed": pr_closed,
        "fix_rate": round(pr_merged / max(len(prs), 1) * 100, 1),
        "severity_breakdown": severity_agg,
        "category_breakdown": category_agg,
    }


def fetch_prs_from_github(runs: list[dict]) -> list[dict]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return []

    fork_repos: set[str] = set()
    for run in runs:
        fork_url = run.get("fork_url", "")
        if "github.com/" in fork_url:
            fork_repos.add(fork_url.rstrip("/").split("github.com/")[1])

    prs = []
    seen_urls: set[str] = set()
    for repo_full in fork_repos:
        url = f"https://api.github.com/repos/{repo_full}/pulls?state=all&per_page=100"
        try:
            resp = requests.get(url, headers=_gh_headers(), timeout=30)
            if resp.status_code != 200:
                continue
            for pr in resp.json():
                title = pr.get("title", "")
                if not re.search(r"fix\(CQLF-", title):
                    continue
                html_url = pr.get("html_url", "")
                if html_url in seen_urls:
                    continue
                seen_urls.add(html_url)
                issue_ids = re.findall(r"CQLF-R\d+-\d+", title)
                prs.append({
                    "pr_number": pr.get("number"),
                    "title": title,
                    "html_url": html_url,
                    "state": pr.get("state", ""),
                    "merged": pr.get("merged_at") is not None,
                    "created_at": pr.get("created_at", ""),
                    "repo": repo_full,
                    "issue_ids": issue_ids,
                    "user": pr.get("user", {}).get("login", ""),
                })
        except requests.RequestException:
            continue
    return prs


def poll_devin_sessions(sessions: list[dict]) -> list[dict]:
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
            resp = requests.get(
                f"{DEVIN_API_BASE}/session/{sid}",
                headers=_devin_headers(),
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                status_str = data.get("status", data.get("status_enum", "unknown"))
                if isinstance(status_str, dict):
                    status_str = status_str.get("status", "unknown")
                s["status"] = status_str
                pr_url = data.get("structured_output", {}).get("pull_request_url", "")
                if not pr_url:
                    pr_url = data.get("result", {}).get("pull_request_url", "")
                if pr_url:
                    s["pr_url"] = pr_url
        except requests.RequestException:
            pass
        updated.append(s)
    return updated


def _save_session_updates(sessions: list[dict]) -> None:
    run_sessions: dict[str, list[dict]] = {}
    for s in sessions:
        label = s.get("run_label", "")
        if label not in run_sessions:
            run_sessions[label] = []
        run_sessions[label].append(s)

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


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/runs")
def api_runs():
    return jsonify(load_runs())


@app.route("/api/sessions")
def api_sessions():
    runs = load_runs()
    return jsonify(aggregate_sessions(runs))


@app.route("/api/prs")
def api_prs():
    runs = load_runs()
    return jsonify(fetch_prs_from_github(runs))


@app.route("/api/stats")
def api_stats():
    runs = load_runs()
    sessions = aggregate_sessions(runs)
    prs = fetch_prs_from_github(runs)
    return jsonify(aggregate_stats(runs, sessions, prs))


@app.route("/api/poll", methods=["POST"])
def api_poll():
    runs = load_runs()
    sessions = aggregate_sessions(runs)
    updated = poll_devin_sessions(sessions)
    _save_session_updates(updated)
    return jsonify({"sessions": updated, "polled": len(updated)})


@app.route("/api/poll-prs", methods=["POST"])
def api_poll_prs():
    runs = load_runs()
    prs = fetch_prs_from_github(runs)
    return jsonify({"prs": prs, "total": len(prs)})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    token = os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")
    if not token or not action_repo:
        return jsonify({"error": "GITHUB_TOKEN and ACTION_REPO required"}), 400

    url = f"https://api.github.com/repos/{action_repo}/contents/telemetry/runs"
    resp = requests.get(url, headers=_gh_headers(), timeout=30)
    if resp.status_code != 200:
        return jsonify({"error": f"GitHub API returned {resp.status_code}"}), 502

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    for item in resp.json():
        if not item.get("name", "").endswith(".json"):
            continue
        local_path = RUNS_DIR / item["name"]
        if local_path.exists():
            continue
        dl_resp = requests.get(item["download_url"], timeout=30)
        if dl_resp.status_code == 200:
            local_path.write_text(dl_resp.text)
            downloaded += 1

    return jsonify({"downloaded": downloaded, "total_files": len(list(RUNS_DIR.glob("*.json")))})


if __name__ == "__main__":
    from dotenv import load_dotenv
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    app.run(host="0.0.0.0", port=5000, debug=True)
