#!/usr/bin/env python3
"""Centralized telemetry server for CodeQL Devin Fixer.

Aggregates data from all action runs across every target repository into a
single dashboard.  Run data is stored as JSON files under ``telemetry/runs/``
in this repository -- each action run pushes one file via the GitHub Contents
API (see ``scripts/persist_telemetry.py``).

Scalability
-----------
* **In-memory cache** -- run data is loaded once and refreshed only when the
  runs directory changes (based on file count + mtime of newest file).  This
  avoids re-reading every JSON file on each request.
* **Pagination** -- ``/api/runs``, ``/api/sessions``, and ``/api/prs`` accept
  ``page`` and ``per_page`` query parameters.  Defaults: page=1, per_page=50.
* **Cached PR / session data** -- GitHub and Devin API results are cached for
  a configurable TTL (default 120 s) so repeated page loads don't hammer
  external APIs.

Endpoints
---------
GET  /                  Serve the dashboard UI.
GET  /api/runs          Return paginated run records.
GET  /api/sessions      Return paginated Devin sessions (aggregated from runs).
GET  /api/prs           Return paginated PRs fetched from the GitHub API.
GET  /api/stats         Return aggregated statistics.
POST /api/poll          Poll Devin API for live session statuses.
POST /api/poll-prs      Poll GitHub API for PR statuses.
POST /api/refresh       Pull latest telemetry data from the repo.

Configuration is via environment variables or a ``.env`` file in this
directory:

GITHUB_TOKEN   PAT with ``repo`` scope (for GitHub API calls).
DEVIN_API_KEY  Devin API key (for polling session statuses).
ACTION_REPO    The repo where telemetry lives, e.g. ``your-username/codeql-devin-fixer``.
CACHE_TTL      Seconds to cache external API results (default 120).
"""

import functools
import hmac
import json
import os
import pathlib
import time
import threading
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, jsonify, render_template, request as flask_request
from flask_cors import CORS

from config import RUNS_DIR, gh_headers
from github_service import fetch_prs_from_github, link_prs_to_sessions
from devin_service import poll_devin_sessions, save_session_updates
from issue_tracking import track_issues_across_runs
from aggregation import aggregate_sessions, aggregate_stats, build_repos_dict

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent.parent / "repo_registry.json"

app = Flask(__name__)
CORS(app)


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if flask_request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


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


class _Cache:
    """Thread-safe in-memory cache with TTL for external API results."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: list[dict] = []
        self._runs_fingerprint: str = ""
        self._prs: list[dict] = []
        self._prs_ts: float = 0.0
        self._sessions_polled: list[dict] = []
        self._sessions_ts: float = 0.0

    @property
    def ttl(self) -> float:
        return float(os.environ.get("CACHE_TTL", "120"))

    def _runs_fp(self) -> str:
        if not RUNS_DIR.is_dir():
            return ""
        files = sorted(RUNS_DIR.glob("*.json"))
        if not files:
            return ""
        newest_mtime = max(f.stat().st_mtime for f in files)
        return f"{len(files)}:{newest_mtime}"

    def get_runs(self) -> list[dict]:
        fp = self._runs_fp()
        with self._lock:
            if fp == self._runs_fingerprint and self._runs:
                return self._runs
        runs = _load_runs_from_disk()
        with self._lock:
            self._runs = runs
            self._runs_fingerprint = fp
        return runs

    def invalidate_runs(self) -> None:
        with self._lock:
            self._runs_fingerprint = ""
            self._runs = []

    def get_prs(self, runs: list[dict]) -> list[dict]:
        with self._lock:
            if self._prs and (time.time() - self._prs_ts) < self.ttl:
                return self._prs
        prs = fetch_prs_from_github(runs)
        with self._lock:
            self._prs = prs
            self._prs_ts = time.time()
        return prs

    def set_prs(self, prs: list[dict]) -> None:
        with self._lock:
            self._prs = prs
            self._prs_ts = time.time()

    def get_polled_sessions(self) -> list[dict] | None:
        with self._lock:
            if self._sessions_polled and (time.time() - self._sessions_ts) < self.ttl:
                return self._sessions_polled
        return None

    def set_polled_sessions(self, sessions: list[dict]) -> None:
        with self._lock:
            self._sessions_polled = sessions
            self._sessions_ts = time.time()


cache = _Cache()


def _load_runs_from_disk() -> list[dict]:
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


def _paginate(items: list, page: int, per_page: int) -> dict:
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


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/repo/<path:repo_url>")
def repo_page(repo_url):
    full_url = "https://github.com/" + repo_url
    return render_template("repo.html", repo_url=full_url, repo_short=repo_url)


@app.route("/api/repo/<path:repo_url>")
def api_repo_detail(repo_url):
    full_url = "https://github.com/" + repo_url
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs)

    repo_runs = [r for r in runs if r.get("target_repo", "") == full_url]
    repo_sessions = [s for s in sessions if s.get("target_repo", "") == full_url]

    repo_info = None
    all_repos = build_repos_dict(runs, sessions, prs)
    for r in all_repos:
        if r["repo"] == full_url:
            repo_info = r
            break

    fork_url = repo_info["fork_url"] if repo_info else ""
    repo_prs = [p for p in prs if fork_url and p.get("repo", "") and fork_url and p["repo"] in fork_url]

    pr_merged = sum(1 for p in repo_prs if p.get("merged", False))
    pr_open = sum(1 for p in repo_prs if p.get("state") == "open")
    pr_closed = sum(1 for p in repo_prs if p.get("state") == "closed" and not p.get("merged", False))

    severity_agg: dict[str, int] = {}
    category_agg: dict[str, int] = {}
    for run in repo_runs:
        for tier, count in run.get("severity_breakdown", {}).items():
            severity_agg[tier] = severity_agg.get(tier, 0) + count
        for cat, count in run.get("category_breakdown", {}).items():
            category_agg[cat] = category_agg.get(cat, 0) + count

    sessions_created = len([s for s in repo_sessions if s.get("session_id")])
    sessions_finished = len([s for s in repo_sessions if s.get("status") in ("finished", "stopped")])

    stats = {
        "total_runs": len(repo_runs),
        "total_issues": sum(r.get("issues_found", 0) for r in repo_runs),
        "sessions_created": sessions_created,
        "sessions_finished": sessions_finished,
        "prs_total": len(repo_prs),
        "prs_merged": pr_merged,
        "prs_open": pr_open,
        "prs_closed": pr_closed,
        "fix_rate": round(pr_merged / max(len(repo_prs), 1) * 100, 1),
        "severity_breakdown": severity_agg,
        "category_breakdown": category_agg,
    }

    page, per_page = _get_pagination()
    sorted_runs = sorted(repo_runs, key=lambda r: r.get("run_number", 0), reverse=True)

    issues = track_issues_across_runs(repo_runs)

    return jsonify({
        "stats": stats,
        "runs": _paginate(sorted_runs, page, per_page),
        "sessions": _paginate(repo_sessions, page, per_page),
        "prs": _paginate(repo_prs, page, per_page),
        "issues": _paginate(issues, page, per_page),
    })


@app.route("/api/runs")
def api_runs():
    runs = cache.get_runs()
    page, per_page = _get_pagination()
    sorted_runs = sorted(runs, key=lambda r: r.get("run_number", 0), reverse=True)
    return jsonify(_paginate(sorted_runs, page, per_page))


@app.route("/api/sessions")
def api_sessions():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs)
    sessions = link_prs_to_sessions(sessions, prs)
    page, per_page = _get_pagination()
    return jsonify(_paginate(sessions, page, per_page))


@app.route("/api/prs")
def api_prs():
    runs = cache.get_runs()
    prs = cache.get_prs(runs)
    page, per_page = _get_pagination()
    return jsonify(_paginate(prs, page, per_page))


def _filter_by_period(runs: list[dict], period: str) -> list[dict]:
    """Filter runs to those within the given period (7d, 30d, 90d)."""
    if not period or period == "all":
        return runs
    days_map = {"7d": 7, "30d": 30, "90d": 90}
    days = days_map.get(period)
    if days is None:
        return runs
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return [r for r in runs if r.get("timestamp", "") >= cutoff]


@app.route("/api/stats")
def api_stats():
    runs = cache.get_runs()
    period = flask_request.args.get("period", "all")
    filtered_runs = _filter_by_period(runs, period)
    sessions = aggregate_sessions(filtered_runs)
    prs = cache.get_prs(runs)
    if period != "all":
        session_ids = {s["session_id"] for s in sessions if s.get("session_id")}
        all_issue_ids = {iid for s in sessions for iid in s.get("issue_ids", [])}
        prs = [p for p in prs if p.get("session_id") in session_ids
               or any(pid in all_issue_ids for pid in p.get("issue_ids", []))]
    result = aggregate_stats(filtered_runs, sessions, prs)
    result["period"] = period
    return jsonify(result)


@app.route("/api/repos")
def api_repos():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs)
    return jsonify(build_repos_dict(runs, sessions, prs))


@app.route("/api/poll", methods=["POST"])
@require_api_key
def api_poll():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    updated = poll_devin_sessions(sessions)
    if save_session_updates(updated):
        cache.invalidate_runs()
    cache.set_polled_sessions(updated)
    prs = fetch_prs_from_github(runs)
    cache.set_prs(prs)
    updated = link_prs_to_sessions(updated, prs)
    if save_session_updates(updated):
        cache.invalidate_runs()
    return jsonify({"sessions": updated, "polled": len(updated), "prs_found": len(prs)})


@app.route("/api/poll-prs", methods=["POST"])
@require_api_key
def api_poll_prs():
    runs = cache.get_runs()
    prs = fetch_prs_from_github(runs)
    cache.set_prs(prs)
    return jsonify({"prs": prs, "total": len(prs)})


@app.route("/api/refresh", methods=["POST"])
@require_api_key
def api_refresh():
    token = os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")
    if not token or not action_repo:
        return jsonify({"error": "GITHUB_TOKEN and ACTION_REPO required"}), 400

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    gh_page = 1
    while True:
        url = (f"https://api.github.com/repos/{action_repo}"
               f"/contents/telemetry/runs?per_page=100&page={gh_page}")
        resp = requests.get(url, headers=gh_headers(), timeout=30)
        if resp.status_code != 200:
            break
        items = resp.json()
        if not items:
            break
        for item in items:
            if not item.get("name", "").endswith(".json"):
                continue
            local_path = RUNS_DIR / item["name"]
            remote_size = item.get("size", 0)
            if local_path.exists() and local_path.stat().st_size == remote_size:
                continue
            dl_resp = requests.get(item["download_url"], timeout=30)
            if dl_resp.status_code == 200:
                local_path.write_text(dl_resp.text)
                downloaded += 1
        if len(items) < 100:
            break
        gh_page += 1

    cache.invalidate_runs()
    runs = cache.get_runs()
    prs = fetch_prs_from_github(runs)
    cache.set_prs(prs)
    sessions = aggregate_sessions(runs)
    link_prs_to_sessions(sessions, prs)
    if save_session_updates(sessions):
        cache.invalidate_runs()
    return jsonify({
        "downloaded": downloaded,
        "total_files": len(list(RUNS_DIR.glob("*.json"))),
        "prs_found": len(prs),
    })


@app.route("/api/config")
def api_config():
    auth_required = bool(_get_telemetry_api_key())
    response: dict = {"auth_required": auth_required}
    if _is_authenticated():
        response["github_token_set"] = bool(os.environ.get("GITHUB_TOKEN", ""))
        response["devin_api_key_set"] = bool(os.environ.get("DEVIN_API_KEY", ""))
        response["action_repo"] = os.environ.get("ACTION_REPO", "")
    return jsonify(response)


@app.route("/api/backfill", methods=["POST"])
@require_api_key
def api_backfill():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs)
    pr_issue_map: dict[str, str] = {}
    for p in prs:
        for iid in p.get("issue_ids", []):
            if iid:
                pr_issue_map[iid] = p.get("html_url", "")
    patched = 0
    for fp in RUNS_DIR.glob("*.json"):
        try:
            with open(fp) as f:
                run_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        changed = False
        for s in run_data.get("sessions", []):
            old_ids = s.get("issue_ids", [])
            if old_ids and all(iid == "" for iid in old_ids):
                batch_id = s.get("batch_id")
                run_num = run_data.get("run_number")
                if run_num and batch_id is not None:
                    s["issue_ids"] = []
                    changed = True
            if not s.get("pr_url"):
                for iid in s.get("issue_ids", []):
                    if iid in pr_issue_map:
                        s["pr_url"] = pr_issue_map[iid]
                        changed = True
                        break
        if changed:
            patched += 1
            with open(fp, "w") as f:
                json.dump(run_data, f, indent=2)
    if patched:
        cache.invalidate_runs()
    return jsonify({"patched_files": patched})


@app.route("/api/issues")
def api_issues():
    runs = cache.get_runs()
    repo_filter = flask_request.args.get("repo", "")
    if repo_filter:
        runs = [r for r in runs if r.get("target_repo") == repo_filter]
    issues = track_issues_across_runs(runs)
    page, per_page = _get_pagination()
    return jsonify(_paginate(issues, page, per_page))


@app.route("/api/dispatch/preflight")
def api_dispatch_preflight():
    target_repo = flask_request.args.get("target_repo", "")
    if not target_repo:
        return jsonify({"error": "target_repo is required"}), 400

    runs = cache.get_runs()
    prs = cache.get_prs(runs)

    open_prs = [
        p for p in prs
        if p.get("state") == "open" and not p.get("merged", False)
    ]

    sessions = aggregate_sessions(runs)
    repo_open_prs = []
    for p in open_prs:
        pr_repo = p.get("repo", "")
        if not pr_repo:
            continue
        for s in sessions:
            if s.get("target_repo", "") == target_repo and s.get("pr_url", "") == p.get("html_url", ""):
                repo_open_prs.append(p)
                break
        else:
            fork_url = ""
            for run in runs:
                if run.get("target_repo", "") == target_repo:
                    fork_url = run.get("fork_url", "")
                    break
            if fork_url and pr_repo in fork_url:
                repo_open_prs.append(p)

    return jsonify({
        "target_repo": target_repo,
        "open_prs": len(repo_open_prs),
        "prs": [
            {"pr_number": p.get("pr_number"), "title": p.get("title"), "html_url": p.get("html_url")}
            for p in repo_open_prs
        ],
    })


@app.route("/api/dispatch", methods=["POST"])
@require_api_key
def api_dispatch():
    if not _get_telemetry_api_key():
        return jsonify({"error": "TELEMETRY_API_KEY must be configured to use the dispatch endpoint"}), 403
    token = os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")
    if not token:
        return jsonify({"error": "GITHUB_TOKEN not configured"}), 400
    if not action_repo:
        return jsonify({"error": "ACTION_REPO not configured"}), 400

    body = flask_request.get_json(silent=True) or {}
    target_repo = body.get("target_repo", "")
    if not target_repo:
        return jsonify({"error": "target_repo is required"}), 400

    inputs = {
        "target_repo": target_repo,
        "languages": body.get("languages", ""),
        "queries": body.get("queries", "security-extended"),
        "persist_logs": str(body.get("persist_logs", True)).lower(),
        "include_paths": body.get("include_paths", ""),
        "exclude_paths": body.get("exclude_paths", ""),
        "batch_size": str(body.get("batch_size", 5)),
        "max_sessions": str(body.get("max_sessions", 5)),
        "severity_threshold": body.get("severity_threshold", "low"),
        "dry_run": str(body.get("dry_run", False)).lower(),
        "default_branch": body.get("default_branch", "main"),
    }

    url = f"https://api.github.com/repos/{action_repo}/actions/workflows/codeql-fixer.yml/dispatches"
    payload = {"ref": "main", "inputs": inputs}

    try:
        resp = requests.post(url, headers=gh_headers(), json=payload, timeout=30)
        if resp.status_code == 204:
            return jsonify({"success": True, "message": "Workflow dispatched successfully"})
        else:
            error_body = resp.text
            try:
                error_body = resp.json().get("message", resp.text)
            except Exception:
                pass
            return jsonify({"error": f"GitHub API error ({resp.status_code}): {error_body}"}), resp.status_code
    except requests.RequestException as e:
        return jsonify({"error": "Request failed due to a server error"}), 500


def _load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {"version": "1.0", "defaults": {}, "concurrency": {"max_parallel": 3, "delay_seconds": 30}, "repos": []}
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def _save_registry(data: dict) -> None:
    with open(REGISTRY_PATH, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


@app.route("/api/registry")
def api_registry():
    return jsonify(_load_registry())


@app.route("/api/registry", methods=["PUT"])
@require_api_key
def api_registry_update():
    body = flask_request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body is required"}), 400
    registry = _load_registry()
    if "defaults" in body:
        registry["defaults"] = body["defaults"]
    if "concurrency" in body:
        registry["concurrency"] = body["concurrency"]
    if "repos" in body:
        registry["repos"] = body["repos"]
    _save_registry(registry)
    return jsonify(registry)


@app.route("/api/registry/repos", methods=["POST"])
@require_api_key
def api_registry_add_repo():
    body = flask_request.get_json(silent=True) or {}
    repo_url = body.get("repo", "").strip()
    if not repo_url:
        return jsonify({"error": "repo is required"}), 400
    registry = _load_registry()
    for existing in registry.get("repos", []):
        if existing.get("repo") == repo_url:
            return jsonify({"error": "Repo already registered"}), 409
    entry = {
        "repo": repo_url,
        "enabled": body.get("enabled", True),
        "schedule": body.get("schedule", "weekly"),
        "overrides": body.get("overrides", {}),
    }
    registry.setdefault("repos", []).append(entry)
    _save_registry(registry)
    return jsonify(entry), 201


@app.route("/api/registry/repos", methods=["DELETE"])
@require_api_key
def api_registry_remove_repo():
    body = flask_request.get_json(silent=True) or {}
    repo_url = body.get("repo", "").strip()
    if not repo_url:
        return jsonify({"error": "repo is required"}), 400
    registry = _load_registry()
    original_len = len(registry.get("repos", []))
    registry["repos"] = [r for r in registry.get("repos", []) if r.get("repo") != repo_url]
    if len(registry["repos"]) == original_len:
        return jsonify({"error": "Repo not found in registry"}), 404
    _save_registry(registry)
    return jsonify({"removed": repo_url})


if __name__ == "__main__":
    from dotenv import load_dotenv
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
