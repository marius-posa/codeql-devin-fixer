#!/usr/bin/env python3
"""Centralized telemetry server for CodeQL Devin Fixer.

Secrets can be provided in two ways (header takes precedence):
1. Request headers: X-GitHub-Token, X-Devin-API-Key, X-Action-Repo
2. Environment variables: GITHUB_TOKEN, DEVIN_API_KEY, ACTION_REPO
"""

import json
import os
import pathlib as _pathlib
import time
import threading

import requests
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from jinja2 import Environment, FileSystemLoader

try:
    from .config import RUNS_DIR, gh_headers, get_action_repo
    from .github_service import fetch_prs_from_github, link_prs_to_sessions
    from .devin_service import poll_devin_sessions, save_session_updates
    from .issue_tracking import track_issues_across_runs
    from .aggregation import aggregate_sessions, aggregate_stats, build_repos_dict
except ImportError:  # when running as a top-level script (fastapi run app.py)
    from config import RUNS_DIR, gh_headers, get_action_repo
    from github_service import fetch_prs_from_github, link_prs_to_sessions
    from devin_service import poll_devin_sessions, save_session_updates
    from issue_tracking import track_issues_across_runs
    from aggregation import aggregate_sessions, aggregate_stats, build_repos_dict

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_templates_dir = _pathlib.Path(__file__).parent / "templates"
_jinja_env = Environment(loader=FileSystemLoader(str(_templates_dir)), autoescape=True)

app.mount("/static", StaticFiles(directory=str(_pathlib.Path(__file__).parent / "static")), name="static")


def _get_secrets(request: Request) -> tuple[str, str, str]:
    gh_token = request.headers.get("x-github-token", "") or os.environ.get("GITHUB_TOKEN", "")
    devin_key = request.headers.get("x-devin-api-key", "") or os.environ.get("DEVIN_API_KEY", "")
    action_repo = request.headers.get("x-action-repo", "") or get_action_repo()
    return gh_token, devin_key, action_repo


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

    def get_prs(self, runs: list[dict], token: str = "") -> list[dict]:
        with self._lock:
            if self._prs and (time.time() - self._prs_ts) < self.ttl:
                return self._prs
        prs = fetch_prs_from_github(runs, token=token)
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


def _get_pagination(request: Request) -> tuple[int, int]:
    page = max(1, int(request.query_params.get("page", 1)))
    per_page = min(200, max(1, int(request.query_params.get("per_page", 50))))
    return page, per_page


@app.get("/", response_class=HTMLResponse)
async def index():
    template = _jinja_env.get_template("dashboard.html")
    return HTMLResponse(template.render())


@app.get("/repo/{repo_url:path}", response_class=HTMLResponse)
async def repo_page(repo_url: str):
    full_url = "https://github.com/" + repo_url
    template = _jinja_env.get_template("repo.html")
    return HTMLResponse(template.render(repo_url=full_url, repo_short=repo_url))


@app.get("/api/repo/{repo_url:path}")
async def api_repo_detail(repo_url: str, request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    full_url = "https://github.com/" + repo_url
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs, token=gh_token)

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

    page, per_page = _get_pagination(request)
    sorted_runs = sorted(repo_runs, key=lambda r: r.get("run_number", 0), reverse=True)
    issues = track_issues_across_runs(repo_runs)

    return {
        "stats": stats,
        "runs": _paginate(sorted_runs, page, per_page),
        "sessions": _paginate(repo_sessions, page, per_page),
        "prs": _paginate(repo_prs, page, per_page),
        "issues": _paginate(issues, page, per_page),
    }


@app.get("/api/runs")
async def api_runs(request: Request):
    runs = cache.get_runs()
    page, per_page = _get_pagination(request)
    sorted_runs = sorted(runs, key=lambda r: r.get("run_number", 0), reverse=True)
    return _paginate(sorted_runs, page, per_page)


@app.get("/api/sessions")
async def api_sessions(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs, token=gh_token)
    sessions = link_prs_to_sessions(sessions, prs)
    page, per_page = _get_pagination(request)
    return _paginate(sessions, page, per_page)


@app.get("/api/prs")
async def api_prs(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    prs = cache.get_prs(runs, token=gh_token)
    page, per_page = _get_pagination(request)
    return _paginate(prs, page, per_page)


@app.get("/api/stats")
async def api_stats(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs, token=gh_token)
    return aggregate_stats(runs, sessions, prs)


@app.get("/api/repos")
async def api_repos(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs, token=gh_token)
    return build_repos_dict(runs, sessions, prs)


@app.post("/api/poll")
async def api_poll(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    updated = poll_devin_sessions(sessions, api_key=devin_key)
    if save_session_updates(updated):
        cache.invalidate_runs()
    cache.set_polled_sessions(updated)
    prs = fetch_prs_from_github(runs, token=gh_token)
    cache.set_prs(prs)
    updated = link_prs_to_sessions(updated, prs)
    if save_session_updates(updated):
        cache.invalidate_runs()
    return {"sessions": updated, "polled": len(updated), "prs_found": len(prs)}


@app.post("/api/poll-prs")
async def api_poll_prs(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    prs = fetch_prs_from_github(runs, token=gh_token)
    cache.set_prs(prs)
    return {"prs": prs, "total": len(prs)}


@app.post("/api/refresh")
async def api_refresh(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    if not gh_token or not action_repo:
        return JSONResponse(
            {"error": "GitHub token and Action Repo are required. Configure them in Settings."},
            status_code=400,
        )

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    gh_page = 1
    while True:
        url = (f"https://api.github.com/repos/{action_repo}"
               f"/contents/telemetry/runs?per_page=100&page={gh_page}")
        resp = requests.get(url, headers=gh_headers(gh_token), timeout=30)
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
    prs = fetch_prs_from_github(runs, token=gh_token)
    cache.set_prs(prs)
    sessions = aggregate_sessions(runs)
    link_prs_to_sessions(sessions, prs)
    if save_session_updates(sessions):
        cache.invalidate_runs()
    return {
        "downloaded": downloaded,
        "total_files": len(list(RUNS_DIR.glob("*.json"))),
        "prs_found": len(prs),
    }


@app.get("/api/config")
async def api_config(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    return {
        "github_token_set": bool(gh_token),
        "devin_api_key_set": bool(devin_key),
        "action_repo": action_repo,
    }


@app.post("/api/backfill")
async def api_backfill(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    runs = cache.get_runs()
    sessions = aggregate_sessions(runs)
    prs = cache.get_prs(runs, token=gh_token)
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
    return {"patched_files": patched}


@app.get("/api/issues")
async def api_issues(request: Request):
    runs = cache.get_runs()
    repo_filter = request.query_params.get("repo", "")
    if repo_filter:
        runs = [r for r in runs if r.get("target_repo") == repo_filter]
    issues = track_issues_across_runs(runs)
    page, per_page = _get_pagination(request)
    return _paginate(issues, page, per_page)


@app.get("/api/dispatch/preflight")
async def api_dispatch_preflight(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    target_repo = request.query_params.get("target_repo", "")
    if not target_repo:
        return JSONResponse({"error": "target_repo is required"}, status_code=400)

    runs = cache.get_runs()
    prs = cache.get_prs(runs, token=gh_token)

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

    return {
        "target_repo": target_repo,
        "open_prs": len(repo_open_prs),
        "prs": [
            {"pr_number": p.get("pr_number"), "title": p.get("title"), "html_url": p.get("html_url")}
            for p in repo_open_prs
        ],
    }


@app.post("/api/dispatch")
async def api_dispatch(request: Request):
    gh_token, devin_key, action_repo = _get_secrets(request)
    if not gh_token:
        return JSONResponse({"error": "GitHub token not configured. Set it in Settings."}, status_code=400)
    if not action_repo:
        return JSONResponse({"error": "ACTION_REPO not configured. Set it in Settings."}, status_code=400)

    body = await request.json()
    target_repo = body.get("target_repo", "")
    if not target_repo:
        return JSONResponse({"error": "target_repo is required"}, status_code=400)

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
        resp = requests.post(url, headers=gh_headers(gh_token), json=payload, timeout=30)
        if resp.status_code == 204:
            return {"success": True, "message": "Workflow dispatched successfully"}
        else:
            error_body = resp.text
            try:
                error_body = resp.json().get("message", resp.text)
            except Exception:
                pass
            return JSONResponse(
                {"error": f"GitHub API error ({resp.status_code}): {error_body}"},
                status_code=resp.status_code,
            )
    except requests.RequestException:
        return JSONResponse({"error": "Request failed due to a server error"}, status_code=500)


if __name__ == "__main__":
    import uvicorn
    from dotenv import load_dotenv
    env_path = _pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    uvicorn.run(app, host="0.0.0.0", port=5000)
