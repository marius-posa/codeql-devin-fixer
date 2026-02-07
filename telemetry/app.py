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
ACTION_REPO    The repo where telemetry lives, e.g. ``marius-posa/codeql-devin-fixer``.
CACHE_TTL      Seconds to cache external API results (default 120).
"""

import json
import os
import pathlib
import re
import time
import threading
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request as flask_request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

RUNS_DIR = pathlib.Path(__file__).parent / "runs"
DEVIN_API_BASE = "https://api.devin.ai/v1"


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
        prs = _fetch_prs_from_github(runs)
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


def _gh_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _devin_headers() -> dict:
    key = os.environ.get("DEVIN_API_KEY", "")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


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
                "run_id": run.get("run_id", ""),
                "run_url": run.get("run_url", ""),
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

    latest_by_repo: dict[str, dict] = {}
    for run in runs:
        repo = run.get("target_repo", "")
        if repo:
            repos.add(repo)
        total_issues += run.get("issues_found", 0)
        for tier, count in run.get("severity_breakdown", {}).items():
            severity_agg[tier] = severity_agg.get(tier, 0) + count
        for cat, count in run.get("category_breakdown", {}).items():
            category_agg[cat] = category_agg.get(cat, 0) + count
        if repo:
            ts = run.get("timestamp", "")
            prev = latest_by_repo.get(repo)
            if prev is None or ts > prev.get("timestamp", ""):
                latest_by_repo[repo] = run

    latest_issues = sum(
        r.get("issues_found", 0) for r in latest_by_repo.values()
    )
    latest_severity: dict[str, int] = {}
    latest_category: dict[str, int] = {}
    for r in latest_by_repo.values():
        for tier, count in r.get("severity_breakdown", {}).items():
            latest_severity[tier] = latest_severity.get(tier, 0) + count
        for cat, count in r.get("category_breakdown", {}).items():
            latest_category[cat] = latest_category.get(cat, 0) + count

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
        "latest_issues": latest_issues,
        "latest_severity": latest_severity,
        "latest_category": latest_category,
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


def _collect_session_ids(runs: list[dict]) -> set[str]:
    ids: set[str] = set()
    for run in runs:
        for s in run.get("sessions", []):
            sid = s.get("session_id", "")
            if sid and sid != "dry-run":
                clean = sid.replace("devin-", "") if sid.startswith("devin-") else sid
                ids.add(clean)
    return ids


def _match_pr_to_session(pr_body: str, session_ids: set[str]) -> str:
    for sid in session_ids:
        if sid in (pr_body or ""):
            return sid
    return ""


def _fetch_prs_from_github(runs: list[dict]) -> list[dict]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return []

    search_repos: set[str] = set()
    for run in runs:
        for url_field in ("fork_url", "target_repo"):
            raw_url = run.get(url_field, "")
            parsed = urlparse(raw_url)
            if parsed.hostname == "github.com":
                path = parsed.path.strip("/")
                if path:
                    search_repos.add(path)

    session_ids = _collect_session_ids(runs)

    prs: list[dict] = []
    seen_urls: set[str] = set()
    for repo_full in search_repos:
        gh_page = 1
        while True:
            url = (f"https://api.github.com/repos/{repo_full}/pulls"
                   f"?state=all&per_page=100&page={gh_page}")
            try:
                resp = requests.get(url, headers=_gh_headers(), timeout=30)
                if resp.status_code != 200:
                    snippet = (resp.text or "").strip().replace("\n", " ")[:200]
                    print(f"WARNING: PRs API returned {resp.status_code} for {repo_full} page {gh_page}: {snippet}")
                    break
                batch = resp.json()
                if not batch:
                    break
                for pr in batch:
                    title = pr.get("title", "")
                    body = pr.get("body", "") or ""
                    html_url = pr.get("html_url", "")
                    user_login = pr.get("user", {}).get("login", "")

                    has_issue_ref = bool(re.search(r"CQLF-R\d+-\d+", title + body, re.IGNORECASE))
                    matched_session = _match_pr_to_session(title + body, session_ids)

                    if not has_issue_ref and not matched_session:
                        continue
                    if html_url in seen_urls:
                        continue
                    seen_urls.add(html_url)

                    issue_ids = re.findall(r"CQLF-R\d+-\d+", title + body, re.IGNORECASE)
                    prs.append({
                        "pr_number": pr.get("number"),
                        "title": title,
                        "html_url": html_url,
                        "state": pr.get("state", ""),
                        "merged": pr.get("merged_at") is not None,
                        "created_at": pr.get("created_at", ""),
                        "repo": repo_full,
                        "issue_ids": list(dict.fromkeys(issue_ids)),
                        "user": user_login,
                        "session_id": matched_session,
                    })
                if len(batch) < 100:
                    break
                gh_page += 1
            except requests.RequestException as exc:
                print(f"ERROR: fetching PRs from GitHub failed: {exc}")
                break
    return prs


def _link_prs_to_sessions(
    sessions: list[dict], prs: list[dict],
) -> list[dict]:
    pr_by_session: dict[str, str] = {}
    pr_by_issue: dict[str, str] = {}
    for p in prs:
        sid = p.get("session_id", "")
        if sid:
            pr_by_session[sid] = p.get("html_url", "")
        for iid in p.get("issue_ids", []):
            if iid:
                pr_by_issue[iid] = p.get("html_url", "")

    for s in sessions:
        if s.get("pr_url"):
            continue
        sid = s.get("session_id", "")
        clean = sid.replace("devin-", "") if sid.startswith("devin-") else sid
        if clean in pr_by_session:
            s["pr_url"] = pr_by_session[clean]
            continue
        for iid in s.get("issue_ids", []):
            if iid in pr_by_issue:
                s["pr_url"] = pr_by_issue[iid]
                break
    return sessions


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
            clean_sid = sid.replace("devin-", "") if sid.startswith("devin-") else sid
            resp = requests.get(
                f"{DEVIN_API_BASE}/sessions/{clean_sid}",
                headers=_devin_headers(),
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
    cache.invalidate_runs()


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
    all_repos = _build_repos_dict(runs, sessions, prs)
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

    issues = _track_issues_across_runs(repo_runs)

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
    sessions = _link_prs_to_sessions(sessions, prs)
    page, per_page = _get_pagination()
    return jsonify(_paginate(sessions, page, per_page))


@app.route("/api/prs")
def api_prs():
    runs = cache.get_runs()
    prs = cache.get_prs(runs)
    page, per_page = _get_pagination()
    return jsonify(_paginate(prs, page, per_page))


@app.route("/api/stats")
def api_stats():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs)
    return jsonify(aggregate_stats(runs, sessions, prs))


def _build_repos_dict(runs: list[dict], sessions: list[dict], prs: list[dict]) -> list[dict]:
    repos: dict[str, dict] = {}
    for run in runs:
        repo = run.get("target_repo", "")
        if not repo:
            continue
        if repo not in repos:
            repos[repo] = {
                "repo": repo,
                "fork_url": run.get("fork_url", ""),
                "runs": 0,
                "issues_found": 0,
                "sessions_created": 0,
                "sessions_finished": 0,
                "prs_total": 0,
                "prs_merged": 0,
                "prs_open": 0,
                "severity_breakdown": {},
                "category_breakdown": {},
                "last_run": "",
            }
        r = repos[repo]
        r["runs"] += 1
        r["issues_found"] += run.get("issues_found", 0)
        for tier, count in run.get("severity_breakdown", {}).items():
            r["severity_breakdown"][tier] = r["severity_breakdown"].get(tier, 0) + count
        for cat, count in run.get("category_breakdown", {}).items():
            r["category_breakdown"][cat] = r["category_breakdown"].get(cat, 0) + count
        ts = run.get("timestamp", "")
        if ts > r["last_run"]:
            r["last_run"] = ts
    for s in sessions:
        repo = s.get("target_repo", "")
        if repo in repos:
            repos[repo]["sessions_created"] += 1
            if s.get("status") in ("finished", "stopped"):
                repos[repo]["sessions_finished"] += 1
    for p in prs:
        fork_full = p.get("repo", "")
        matched_repo = ""
        for repo, info in repos.items():
            fork_url = info.get("fork_url", "")
            if fork_full and fork_full in fork_url:
                matched_repo = repo
                break
        if matched_repo:
            repos[matched_repo]["prs_total"] += 1
            if p.get("merged"):
                repos[matched_repo]["prs_merged"] += 1
            elif p.get("state") == "open":
                repos[matched_repo]["prs_open"] += 1
    return sorted(repos.values(), key=lambda r: r["last_run"], reverse=True)


@app.route("/api/repos")
def api_repos():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs)
    return jsonify(_build_repos_dict(runs, sessions, prs))


@app.route("/api/poll", methods=["POST"])
def api_poll():
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    updated = poll_devin_sessions(sessions)
    _save_session_updates(updated)
    cache.set_polled_sessions(updated)
    prs = _fetch_prs_from_github(runs)
    cache.set_prs(prs)
    updated = _link_prs_to_sessions(updated, prs)
    _save_session_updates(updated)
    return jsonify({"sessions": updated, "polled": len(updated), "prs_found": len(prs)})


@app.route("/api/poll-prs", methods=["POST"])
def api_poll_prs():
    runs = cache.get_runs()
    prs = _fetch_prs_from_github(runs)
    cache.set_prs(prs)
    return jsonify({"prs": prs, "total": len(prs)})


@app.route("/api/refresh", methods=["POST"])
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
        resp = requests.get(url, headers=_gh_headers(), timeout=30)
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
    prs = _fetch_prs_from_github(runs)
    cache.set_prs(prs)
    sessions = aggregate_sessions(runs)
    _link_prs_to_sessions(sessions, prs)
    _save_session_updates(sessions)
    return jsonify({
        "downloaded": downloaded,
        "total_files": len(list(RUNS_DIR.glob("*.json"))),
        "prs_found": len(prs),
    })


@app.route("/api/config")
def api_config():
    return jsonify({
        "github_token_set": bool(os.environ.get("GITHUB_TOKEN", "")),
        "devin_api_key_set": bool(os.environ.get("DEVIN_API_KEY", "")),
        "action_repo": os.environ.get("ACTION_REPO", ""),
    })


@app.route("/api/backfill", methods=["POST"])
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


def _track_issues_across_runs(runs: list[dict]) -> list[dict]:
    """Classify every unique issue fingerprint as recurring / new / fixed.

    Scalability
    -----------
    All lookups use dicts so the function is **O(total_fingerprint_entries)**
    regardless of how many unique issues exist -- suitable for 10 000+ issues
    across hundreds of runs.

    Robustness
    ----------
    Runs that pre-date the fingerprinting feature (no ``issue_fingerprints``
    key) are counted as *participating runs* for their repo so that an issue
    present in one fingerprinted run can still be marked "recurring" if the
    same repo had earlier runs without fingerprint data.
    """
    if not runs:
        return []

    sorted_runs = sorted(runs, key=lambda r: r.get("timestamp", ""))

    fp_history: dict[str, list[dict]] = {}
    fp_metadata: dict[str, dict] = {}

    runs_per_repo: dict[str, int] = {}
    runs_with_fps_per_repo: dict[str, int] = {}

    for run in sorted_runs:
        repo = run.get("target_repo", "")
        if repo:
            runs_per_repo[repo] = runs_per_repo.get(repo, 0) + 1

        fingerprints = run.get("issue_fingerprints", [])
        if not fingerprints:
            continue

        if repo:
            runs_with_fps_per_repo[repo] = runs_with_fps_per_repo.get(repo, 0) + 1

        for iss in fingerprints:
            fp = iss.get("fingerprint", "")
            if not fp:
                continue
            if fp not in fp_history:
                fp_history[fp] = []
            fp_history[fp].append({
                "run_number": run.get("run_number"),
                "timestamp": run.get("timestamp", ""),
                "issue_id": iss.get("id", ""),
                "target_repo": repo,
            })
            if fp not in fp_metadata:
                fp_metadata[fp] = {
                    "rule_id": iss.get("rule_id", ""),
                    "severity_tier": iss.get("severity_tier", ""),
                    "cwe_family": iss.get("cwe_family", ""),
                    "file": iss.get("file", ""),
                    "start_line": iss.get("start_line", 0),
                }

    latest_run_per_repo: dict[str, dict] = {}
    for run in sorted_runs:
        repo = run.get("target_repo", "")
        if repo:
            latest_run_per_repo[repo] = run
    latest_fps: set[str] = set()
    for run in latest_run_per_repo.values():
        for iss in run.get("issue_fingerprints", []):
            fp = iss.get("fingerprint", "")
            if fp:
                latest_fps.add(fp)

    result: list[dict] = []
    for fp, appearances in fp_history.items():
        first = appearances[0]
        latest = appearances[-1]
        run_numbers = [a["run_number"] for a in appearances]
        repo = first["target_repo"]

        has_older_runs_without_fps = (
            runs_per_repo.get(repo, 0) > runs_with_fps_per_repo.get(repo, 0)
        )

        if fp in latest_fps:
            if len(appearances) > 1 or has_older_runs_without_fps:
                status = "recurring"
            else:
                status = "new"
        else:
            status = "fixed"

        meta = fp_metadata.get(fp, {})
        result.append({
            "fingerprint": fp,
            "rule_id": meta.get("rule_id", ""),
            "severity_tier": meta.get("severity_tier", ""),
            "cwe_family": meta.get("cwe_family", ""),
            "file": meta.get("file", ""),
            "start_line": meta.get("start_line", 0),
            "status": status,
            "first_seen_run": first["run_number"],
            "first_seen_date": first["timestamp"],
            "last_seen_run": latest["run_number"],
            "last_seen_date": latest["timestamp"],
            "target_repo": repo,
            "appearances": len(appearances),
            "run_numbers": run_numbers,
            "latest_issue_id": latest["issue_id"],
        })

    _STATUS_ORDER = {"recurring": 0, "new": 1, "fixed": 2}
    result.sort(key=lambda x: (
        _STATUS_ORDER.get(x["status"], 3),
        x.get("last_seen_date", ""),
    ))
    return result


@app.route("/api/issues")
def api_issues():
    runs = cache.get_runs()
    repo_filter = flask_request.args.get("repo", "")
    if repo_filter:
        runs = [r for r in runs if r.get("target_repo") == repo_filter]
    issues = _track_issues_across_runs(runs)
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
def api_dispatch():
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
        resp = requests.post(url, headers=_gh_headers(), json=payload, timeout=30)
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
        return jsonify({"error": f"Request failed: {str(e)}"}), 500


if __name__ == "__main__":
    from dotenv import load_dotenv
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    app.run(host="0.0.0.0", port=5000, debug=True)
