#!/usr/bin/env python3
"""Centralized telemetry server for CodeQL Devin Fixer.

Aggregates data from all action runs across every target repository into a
single dashboard.  Run data is stored in a SQLite database (migrated from
JSON files under ``telemetry/runs/``).
"""

import functools
import hmac
import io
import json
import logging
import os
import pathlib

import requests
from flask import Flask, jsonify, render_template, request as flask_request, send_file
from flask_cors import CORS

from config import RUNS_DIR, gh_headers
from database import (
    get_connection,
    insert_run,
    query_runs,
    query_all_runs,
    query_sessions,
    query_all_sessions,
    query_prs,
    query_all_prs,
    query_stats,
    query_repos,
    query_issues,
    search_issues,
    backfill_pr_urls,
    insert_audit_log,
    query_audit_logs,
    export_audit_logs,
)
from migrate_json_to_sqlite import ensure_db_populated
from github_service import fetch_prs_from_github_to_db, link_prs_to_sessions_db
from devin_service import poll_devin_sessions_db
from aggregation import compute_sla_summary
from verification import (
    load_verification_records,
    build_session_verification_map,
    build_fingerprint_fix_map,
    aggregate_verification_stats,
)
from oauth import oauth_bp, is_oauth_configured, get_current_user, filter_by_user_access
from pdf_report import generate_pdf
from demo_data import (
    is_demo_data_loaded,
    load_demo_data_into_db,
    clear_demo_data_from_db,
    get_demo_data_summary,
    load_demo_data_from_files,
    save_demo_data_to_files,
    build_all_demo_data,
)

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent.parent / "repo_registry.json"
SAMPLE_DATA_DIR = pathlib.Path(__file__).parent / "sample_data"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
CORS(app)
app.register_blueprint(oauth_bp)

ensure_db_populated(RUNS_DIR, SAMPLE_DATA_DIR)


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


def _get_audit_user() -> str:
    user = get_current_user()
    if user:
        return user.get("login", "unknown")
    if _is_authenticated():
        return "api-key"
    return "anonymous"


def _audit(action: str, resource: str = "", details: str = "") -> None:
    try:
        conn = get_connection()
        try:
            insert_audit_log(conn, _get_audit_user(), action, resource, details)
        finally:
            conn.close()
    except Exception:
        logging.getLogger(__name__).warning("audit log write failed: action=%s", action, exc_info=True)


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
    conn = get_connection()
    try:
        runs = query_all_runs(conn, target_repo=full_url)
        sessions = query_all_sessions(conn, target_repo=full_url)
        all_prs = query_all_prs(conn)

        repo_info = None
        all_repos = query_repos(conn)
        for r in all_repos:
            if r["repo"] == full_url:
                repo_info = r
                break

        fork_url = repo_info["fork_url"] if repo_info else ""
        repo_prs = [p for p in all_prs if fork_url and p.get("repo", "") and p["repo"] in fork_url]

        pr_merged = sum(1 for p in repo_prs if p.get("merged", False))
        pr_open = sum(1 for p in repo_prs if p.get("state") == "open")
        pr_closed = sum(1 for p in repo_prs if p.get("state") == "closed" and not p.get("merged", False))

        severity_agg: dict[str, int] = {}
        category_agg: dict[str, int] = {}
        for run in runs:
            for tier, count in run.get("severity_breakdown", {}).items():
                severity_agg[tier] = severity_agg.get(tier, 0) + count
            for cat, count in run.get("category_breakdown", {}).items():
                category_agg[cat] = category_agg.get(cat, 0) + count

        sessions_created = len([s for s in sessions if s.get("session_id")])
        sessions_finished = len([s for s in sessions if s.get("status") in ("finished", "stopped")])

        stats = {
            "total_runs": len(runs),
            "total_issues": sum(r.get("issues_found", 0) for r in runs),
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
        sorted_runs = sorted(runs, key=lambda r: r.get("run_number", 0), reverse=True)
        issues = query_issues(conn, target_repo=full_url)

        return jsonify({
            "stats": stats,
            "runs": _paginate(sorted_runs, page, per_page),
            "sessions": _paginate(sessions, page, per_page),
            "prs": _paginate(repo_prs, page, per_page),
            "issues": _paginate(issues, page, per_page),
        })
    finally:
        conn.close()


@app.route("/api/runs")
def api_runs():
    page, per_page = _get_pagination()
    conn = get_connection()
    try:
        return jsonify(query_runs(conn, page=page, per_page=per_page))
    finally:
        conn.close()


@app.route("/api/sessions")
def api_sessions():
    page, per_page = _get_pagination()
    conn = get_connection()
    try:
        result = query_sessions(conn, page=page, per_page=per_page)
        all_prs = query_all_prs(conn)
        _link_prs_to_session_items(result["items"], all_prs)
        return jsonify(result)
    finally:
        conn.close()


def _link_prs_to_session_items(sessions: list[dict], prs: list[dict]) -> None:
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


@app.route("/api/prs")
def api_prs():
    page, per_page = _get_pagination()
    conn = get_connection()
    try:
        return jsonify(query_prs(conn, page=page, per_page=per_page))
    finally:
        conn.close()


@app.route("/api/stats")
def api_stats():
    period = flask_request.args.get("period", "all")
    conn = get_connection()
    try:
        result = query_stats(conn, period=period)
        result["period"] = period
        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/repos")
def api_repos():
    conn = get_connection()
    try:
        return jsonify(query_repos(conn))
    finally:
        conn.close()


@app.route("/api/poll", methods=["POST"])
@require_api_key
def api_poll():
    conn = get_connection()
    try:
        sessions = query_all_sessions(conn)
        updated = poll_devin_sessions_db(conn, sessions)
        conn.commit()
        prs_count = fetch_prs_from_github_to_db(conn)
        conn.commit()
        link_prs_to_sessions_db(conn)
        conn.commit()
        _audit("poll_sessions", details=json.dumps({"polled": len(updated), "prs_found": prs_count}))
        return jsonify({"sessions": updated, "polled": len(updated), "prs_found": prs_count})
    finally:
        conn.close()


@app.route("/api/poll-prs", methods=["POST"])
@require_api_key
def api_poll_prs():
    conn = get_connection()
    try:
        prs_count = fetch_prs_from_github_to_db(conn)
        conn.commit()
        all_prs = query_all_prs(conn)
        _audit("poll_prs", details=json.dumps({"prs_found": prs_count}))
        return jsonify({"prs": all_prs, "total": prs_count})
    finally:
        conn.close()


@app.route("/api/refresh", methods=["POST"])
@require_api_key
def api_refresh():
    token = os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")
    if not token or not action_repo:
        return jsonify({"error": "GITHUB_TOKEN and ACTION_REPO required"}), 400

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    downloaded = 0
    try:
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
                    try:
                        data = dl_resp.json()
                        result = insert_run(conn, data, item["name"])
                        if result is not None:
                            downloaded += 1
                    except (json.JSONDecodeError, ValueError):
                        pass
            if len(items) < 100:
                break
            gh_page += 1

        conn.commit()
        prs_count = fetch_prs_from_github_to_db(conn)
        conn.commit()
        link_prs_to_sessions_db(conn)
        conn.commit()

        total_files = len(list(RUNS_DIR.glob("*.json")))
        _audit("refresh_runs", details=json.dumps({"downloaded": downloaded, "total_files": total_files}))
        return jsonify({
            "downloaded": downloaded,
            "total_files": total_files,
            "prs_found": prs_count,
        })
    finally:
        conn.close()


@app.route("/api/config")
def api_config():
    auth_required = bool(_get_telemetry_api_key())
    response: dict = {"auth_required": auth_required}
    if _is_authenticated():
        response["github_token_set"] = bool(os.environ.get("GITHUB_TOKEN", ""))
        response["devin_api_key_set"] = bool(os.environ.get("DEVIN_API_KEY", ""))
        response["action_repo"] = os.environ.get("ACTION_REPO", "")
    response["oauth_configured"] = is_oauth_configured()
    user = get_current_user()
    if user:
        response["user"] = user
    return jsonify(response)


@app.route("/api/report/pdf")
def api_report_pdf():
    conn = get_connection()
    try:
        repo_filter = flask_request.args.get("repo", "")
        if repo_filter:
            runs = query_all_runs(conn, target_repo=repo_filter)
        else:
            runs = query_all_runs(conn)
        runs = filter_by_user_access(runs)
        stats = query_stats(conn, target_repo=repo_filter)
        issues = query_issues(conn, target_repo=repo_filter)
        pdf_bytes = generate_pdf(stats, issues, repo_filter=repo_filter)
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        filename = "security-report"
        if repo_filter:
            short = repo_filter.replace("https://github.com/", "").replace("/", "-")
            filename += f"-{short}"
        filename += ".pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
    finally:
        conn.close()


@app.route("/api/backfill", methods=["POST"])
@require_api_key
def api_backfill():
    conn = get_connection()
    try:
        patched = backfill_pr_urls(conn)
        conn.commit()

        patched_files = 0
        all_prs = query_all_prs(conn)
        pr_issue_map: dict[str, str] = {}
        for p in all_prs:
            for iid in p.get("issue_ids", []):
                if iid:
                    pr_issue_map[iid] = p.get("html_url", "")
        for fp in RUNS_DIR.glob("*.json"):
            if fp.name.startswith("verification_"):
                continue
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
                patched_files += 1
                with open(fp, "w") as f:
                    json.dump(run_data, f, indent=2)

        _audit("backfill", details=json.dumps({"patched_files": patched_files, "db_patched": patched}))
        return jsonify({"patched_files": patched_files, "db_patched": patched})
    finally:
        conn.close()


@app.route("/api/issues")
def api_issues():
    conn = get_connection()
    try:
        repo_filter = flask_request.args.get("repo", "")
        issues = query_issues(conn, target_repo=repo_filter)

        verification_records = load_verification_records(RUNS_DIR)
        fp_fix_map = build_fingerprint_fix_map(verification_records)
        for issue in issues:
            fp = issue.get("fingerprint", "")
            if fp in fp_fix_map:
                fix_info = fp_fix_map[fp]
                issue["fixed_by_session"] = fix_info["fixed_by_session"]
                issue["fixed_by_pr"] = fix_info["fixed_by_pr"]
                issue["verified_at"] = fix_info["verified_at"]

        page, per_page = _get_pagination()
        return jsonify(_paginate(issues, page, per_page))
    finally:
        conn.close()


@app.route("/api/issues/search")
def api_issues_search():
    q = flask_request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "q parameter is required"}), 400
    repo_filter = flask_request.args.get("repo", "")
    conn = get_connection()
    try:
        results = search_issues(conn, q, target_repo=repo_filter)
        page, per_page = _get_pagination()
        return jsonify(_paginate(results, page, per_page))
    finally:
        conn.close()


@app.route("/api/sla")
def api_sla():
    conn = get_connection()
    try:
        repo_filter = flask_request.args.get("repo", "")
        issues = query_issues(conn, target_repo=repo_filter)
        return jsonify(compute_sla_summary(issues))
    finally:
        conn.close()


@app.route("/api/verification")
def api_verification():
    verification_records = load_verification_records(RUNS_DIR)
    session_map = build_session_verification_map(verification_records)
    stats = aggregate_verification_stats(verification_records)
    page, per_page = _get_pagination()
    return jsonify({
        "stats": stats,
        "records": _paginate(verification_records, page, per_page),
        "session_map": session_map,
    })



@app.route("/api/dispatch/preflight")
def api_dispatch_preflight():
    target_repo = flask_request.args.get("target_repo", "")
    if not target_repo:
        return jsonify({"error": "target_repo is required"}), 400

    conn = get_connection()
    try:
        all_prs = query_all_prs(conn)
        open_prs = [
            p for p in all_prs
            if p.get("state") == "open" and not p.get("merged", False)
        ]

        sessions = query_all_sessions(conn)
        runs = query_all_runs(conn)

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
    finally:
        conn.close()


@app.route("/api/dispatch", methods=["POST"])
@require_api_key
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
        resp = requests.post(url, headers=gh_headers(), json=payload, timeout=30)
        if resp.status_code == 204:
            _audit("dispatch_workflow", resource=target_repo, details=json.dumps(inputs))
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


_ORCHESTRATOR_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
_ORCHESTRATOR_STATE_PATH = pathlib.Path(__file__).resolve().parent / "orchestrator_state.json"
_ORCHESTRATOR_REGISTRY_PATH = pathlib.Path(__file__).resolve().parent.parent / "repo_registry.json"


def _load_orchestrator_state() -> dict:
    if not _ORCHESTRATOR_STATE_PATH.exists():
        return {
            "last_cycle": None,
            "rate_limiter": {},
            "dispatch_history": {},
            "objective_progress": [],
            "scan_schedule": {},
        }
    try:
        with open(_ORCHESTRATOR_STATE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {
            "last_cycle": None,
            "rate_limiter": {},
            "dispatch_history": {},
            "objective_progress": [],
            "scan_schedule": {},
        }


def _serialize_orch_config(orch_config: dict) -> dict:
    return {
        "global_session_limit": orch_config.get("global_session_limit", 20),
        "global_session_limit_period_hours": orch_config.get("global_session_limit_period_hours", 24),
        "objectives": orch_config.get("objectives", []),
        "alert_on_objective_met": orch_config.get("alert_on_objective_met", False),
        "alert_webhook_url": orch_config.get("alert_webhook_url", ""),
        "alert_on_verified_fix": orch_config.get("alert_on_verified_fix", True),
        "alert_severities": orch_config.get("alert_severities", ["critical", "high"]),
    }


def _load_orchestrator_registry() -> dict:
    if not _ORCHESTRATOR_REGISTRY_PATH.exists():
        return {"version": "2.0", "defaults": {}, "orchestrator": {}, "repos": []}
    with open(_ORCHESTRATOR_REGISTRY_PATH) as f:
        return json.load(f)


@app.route("/api/orchestrator/status")
def api_orchestrator_status():
    state = _load_orchestrator_state()
    registry = _load_orchestrator_registry()
    orch_config = registry.get("orchestrator", {})

    max_sessions = orch_config.get("global_session_limit", 20)
    period_hours = orch_config.get("global_session_limit_period_hours", 24)

    rl_data = state.get("rate_limiter", {})
    timestamps = rl_data.get("created_timestamps", rl_data.get("timestamps", []))
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=period_hours)
    used = 0
    for t in timestamps:
        try:
            ts = datetime.fromisoformat(t.replace("Z", "+00:00")) if isinstance(t, str) else None
            if ts and ts > cutoff:
                used += 1
        except (ValueError, TypeError):
            pass

    conn = get_connection()
    try:
        issues = query_issues(conn)
        state_counts: dict[str, int] = {}
        for issue in issues:
            derived = issue.get("derived_state", issue.get("status", "new"))
            state_counts[derived] = state_counts.get(derived, 0) + 1

        objectives = orch_config.get("objectives", [])
        objective_progress = []
        for obj in objectives:
            obj_name = obj.get("objective", "")
            target = obj.get("target_count", 0)
            severity = obj.get("severity", "")
            current = sum(
                1 for i in issues
                if i.get("derived_state") in ("verified_fixed", "fixed")
                and (not severity or i.get("severity_tier") == severity)
            )
            objective_progress.append({
                "objective": obj_name,
                "target_count": target,
                "current_count": current,
                "met": current >= target,
            })

        return jsonify({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "last_cycle": state.get("last_cycle"),
            "issue_state_breakdown": state_counts,
            "total_issues": len(issues),
            "rate_limit": {
                "used": used,
                "max": max_sessions,
                "remaining": max_sessions - used,
                "period_hours": period_hours,
            },
            "objective_progress": objective_progress,
            "scan_schedule": state.get("scan_schedule", {}),
            "dispatch_history_entries": len(state.get("dispatch_history", {})),
        })
    finally:
        conn.close()


@app.route("/api/orchestrator/plan")
def api_orchestrator_plan():
    import subprocess
    result = subprocess.run(
        ["python3", "-m", "scripts.orchestrator", "plan", "--json"],
        capture_output=True, text=True, timeout=60,
        cwd=str(_ORCHESTRATOR_DIR.parent),
    )
    if result.returncode != 0:
        return jsonify({"error": "Plan computation failed", "stderr": result.stderr[:500]}), 500
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        return jsonify({"error": "Invalid plan output", "raw": result.stdout[:500]}), 500


@app.route("/api/orchestrator/dispatch", methods=["POST"])
@require_api_key
def api_orchestrator_dispatch():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run and not os.environ.get("DEVIN_API_KEY"):
        return jsonify({"error": "DEVIN_API_KEY not configured on server"}), 400

    import subprocess
    cmd = ["python3", "-m", "scripts.orchestrator", "dispatch", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_dispatch", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Dispatch failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid dispatch output", "raw": result.stdout[:500]}), 500


@app.route("/api/orchestrator/scan", methods=["POST"])
@require_api_key
def api_orchestrator_scan():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run:
        missing = [v for v in ("GITHUB_TOKEN", "ACTION_REPO") if not os.environ.get(v)]
        if missing:
            return jsonify({"error": f"Missing env vars: {', '.join(missing)}"}), 400

    import subprocess
    cmd = ["python3", "-m", "scripts.orchestrator", "scan", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_scan", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Scan failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid scan output", "raw": result.stdout[:500]}), 500


@app.route("/api/orchestrator/history")
def api_orchestrator_history():
    fingerprint = flask_request.args.get("fingerprint", "")
    state = _load_orchestrator_state()
    dispatch_history = state.get("dispatch_history", {})

    if fingerprint:
        entries = dispatch_history.get(fingerprint, [])
        if not isinstance(entries, list):
            entries = [entries] if entries else []
        return jsonify({"fingerprint": fingerprint, "entries": entries})

    page, per_page = _get_pagination()
    all_entries: list[dict] = []
    for fp, history in dispatch_history.items():
        if isinstance(history, list):
            for entry in history:
                all_entries.append({**entry, "fingerprint": fp})
        elif isinstance(history, dict):
            all_entries.append({**history, "fingerprint": fp})

    all_entries.sort(key=lambda e: e.get("dispatched_at", ""), reverse=True)
    return jsonify(_paginate(all_entries, page, per_page))


@app.route("/api/orchestrator/cycle", methods=["POST"])
@require_api_key
def api_orchestrator_cycle():
    body = flask_request.get_json(silent=True) or {}
    repo_filter = body.get("repo", "")
    dry_run = body.get("dry_run", False)

    if not dry_run:
        missing = [v for v in ("GITHUB_TOKEN", "ACTION_REPO") if not os.environ.get(v)]
        if missing:
            return jsonify({"error": f"Missing env vars: {', '.join(missing)}"}), 400
        if not os.environ.get("DEVIN_API_KEY"):
            return jsonify({"error": "DEVIN_API_KEY not configured on server"}), 400

    import subprocess
    cmd = ["python3", "-m", "scripts.orchestrator", "cycle", "--json"]
    if repo_filter:
        cmd.extend(["--repo", repo_filter])
    if dry_run:
        cmd.append("--dry-run")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
        cwd=str(_ORCHESTRATOR_DIR.parent),
        env={**os.environ},
    )
    _audit("orchestrator_cycle", resource=repo_filter, details=json.dumps({"dry_run": dry_run}))
    try:
        return jsonify(json.loads(result.stdout))
    except (json.JSONDecodeError, ValueError):
        if result.returncode != 0:
            return jsonify({"error": "Cycle failed", "stderr": result.stderr[:500]}), 500
        return jsonify({"error": "Invalid cycle output", "raw": result.stdout[:500]}), 500


@app.route("/api/orchestrator/config")
def api_orchestrator_config():
    registry = _load_orchestrator_registry()
    orch_config = registry.get("orchestrator", {})
    return jsonify(_serialize_orch_config(orch_config))


@app.route("/api/orchestrator/config", methods=["PUT"])
@require_api_key
def api_orchestrator_config_update():
    body = flask_request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body is required"}), 400

    registry = _load_orchestrator_registry()
    orch_config = registry.get("orchestrator", {})

    allowed_keys = (
        "global_session_limit",
        "global_session_limit_period_hours",
        "objectives",
        "alert_on_objective_met",
        "alert_webhook_url",
        "alert_on_verified_fix",
        "alert_severities",
    )
    for key in allowed_keys:
        if key in body:
            orch_config[key] = body[key]

    registry["orchestrator"] = orch_config
    with open(_ORCHESTRATOR_REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)
        f.write("\n")

    _audit("update_orchestrator_config", details=json.dumps({k: body[k] for k in allowed_keys if k in body}))
    return jsonify(_serialize_orch_config(orch_config))


@app.route("/api/orchestrator/fix-rates")
def api_orchestrator_fix_rates():
    conn = get_connection()
    try:
        issues = query_issues(conn)
        verification_records = load_verification_records(RUNS_DIR)
        fp_fix_map = build_fingerprint_fix_map(verification_records)

        by_cwe: dict[str, dict] = {}
        by_repo: dict[str, dict] = {}
        by_severity: dict[str, dict] = {}

        for issue in issues:
            fp = issue.get("fingerprint", "")
            cwe = issue.get("cwe_family", "unknown") or "unknown"
            repo = issue.get("target_repo", "unknown") or "unknown"
            sev = issue.get("severity_tier", "unknown") or "unknown"
            is_fixed = fp in fp_fix_map or issue.get("derived_state") in ("fixed", "verified_fixed")

            for _group_key, group_dict, group_val in [
                ("cwe", by_cwe, cwe),
                ("repo", by_repo, repo),
                ("severity", by_severity, sev),
            ]:
                if group_val not in group_dict:
                    group_dict[group_val] = {"total": 0, "fixed": 0}
                group_dict[group_val]["total"] += 1
                if is_fixed:
                    group_dict[group_val]["fixed"] += 1

        def _compute_rates(group_dict: dict) -> list[dict]:
            result = []
            for name, counts in sorted(group_dict.items(), key=lambda x: x[1]["total"], reverse=True):
                total = counts["total"]
                fixed = counts["fixed"]
                rate = round(fixed / max(total, 1) * 100, 1)
                result.append({"name": name, "total": total, "fixed": fixed, "fix_rate": rate})
            return result

        total_issues = len(issues)
        total_fixed = sum(
            1 for i in issues
            if i.get("fingerprint", "") in fp_fix_map
            or i.get("derived_state") in ("fixed", "verified_fixed")
        )
        overall_rate = round(total_fixed / max(total_issues, 1) * 100, 1)

        return jsonify({
            "overall": {"total": total_issues, "fixed": total_fixed, "fix_rate": overall_rate},
            "by_cwe_family": _compute_rates(by_cwe),
            "by_repo": _compute_rates(by_repo),
            "by_severity": _compute_rates(by_severity),
        })
    finally:
        conn.close()


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
    updated_keys = [k for k in ("defaults", "concurrency", "orchestrator", "repos") if k in body]
    if "defaults" in body:
        registry["defaults"] = body["defaults"]
    if "concurrency" in body:
        registry["concurrency"] = body["concurrency"]
    if "orchestrator" in body:
        registry["orchestrator"] = body["orchestrator"]
    if "repos" in body:
        registry["repos"] = body["repos"]
    _save_registry(registry)
    _audit("update_registry", details=json.dumps({"updated_sections": updated_keys}))
    return jsonify(registry)


_VALID_IMPORTANCE = ("low", "medium", "high", "critical")
_VALID_SCHEDULE = ("hourly", "daily", "weekly", "monthly")


def _validate_repo_fields(body: dict) -> str | None:
    importance = body.get("importance")
    if importance is not None and importance not in _VALID_IMPORTANCE:
        return f"importance must be one of {', '.join(_VALID_IMPORTANCE)}"
    score = body.get("importance_score")
    if score is not None and (not isinstance(score, (int, float)) or score < 0 or score > 100):
        return "importance_score must be a number between 0 and 100"
    schedule = body.get("schedule")
    if schedule is not None and schedule not in _VALID_SCHEDULE:
        return f"schedule must be one of {', '.join(_VALID_SCHEDULE)}"
    tags = body.get("tags")
    if tags is not None and not isinstance(tags, list):
        return "tags must be an array"
    overrides = body.get("overrides")
    if overrides is not None and not isinstance(overrides, dict):
        return "overrides must be an object"
    return None


@app.route("/api/registry/repos", methods=["POST"])
@require_api_key
def api_registry_add_repo():
    body = flask_request.get_json(silent=True) or {}
    repo_url = body.get("repo", "").strip()
    if not repo_url:
        return jsonify({"error": "repo is required"}), 400
    err = _validate_repo_fields(body)
    if err:
        return jsonify({"error": err}), 400
    registry = _load_registry()
    for existing in registry.get("repos", []):
        if existing.get("repo") == repo_url:
            return jsonify({"error": "Repo already registered"}), 409
    entry = {
        "repo": repo_url,
        "enabled": body.get("enabled", True),
        "importance": body.get("importance", "medium"),
        "importance_score": body.get("importance_score", 50),
        "schedule": body.get("schedule", "weekly"),
        "max_sessions_per_cycle": body.get("max_sessions_per_cycle", 5),
        "auto_scan": body.get("auto_scan", True),
        "auto_dispatch": body.get("auto_dispatch", True),
        "tags": body.get("tags", []),
        "overrides": body.get("overrides", {}),
    }
    registry.setdefault("repos", []).append(entry)
    _save_registry(registry)
    _audit("add_registry_repo", resource=repo_url)
    return jsonify(entry), 201


@app.route("/api/registry/repos/<int:idx>", methods=["PUT"])
@require_api_key
def api_registry_update_repo(idx):
    body = flask_request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body is required"}), 400
    err = _validate_repo_fields(body)
    if err:
        return jsonify({"error": err}), 400
    registry = _load_registry()
    repos = registry.get("repos", [])
    if idx < 0 or idx >= len(repos):
        return jsonify({"error": "Invalid repo index"}), 404

    repo_entry = repos[idx]
    allowed_repo_keys = (
        "enabled", "importance", "importance_score", "schedule",
        "max_sessions_per_cycle", "auto_scan", "auto_dispatch",
        "tags", "overrides",
    )
    for key in allowed_repo_keys:
        if key in body:
            repo_entry[key] = body[key]

    repos[idx] = repo_entry
    registry["repos"] = repos
    _save_registry(registry)
    _audit("update_registry_repo", resource=repo_entry.get("repo", ""), details=json.dumps({"idx": idx, "fields": list(body.keys())}))
    return jsonify(repo_entry)


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
    _audit("remove_registry_repo", resource=repo_url)
    return jsonify({"removed": repo_url})


@app.route("/api/demo-data")
def api_demo_data_status():
    conn = get_connection()
    try:
        loaded = is_demo_data_loaded(conn)
        summary = get_demo_data_summary()
        return jsonify({"loaded": loaded, "summary": summary})
    finally:
        conn.close()


@app.route("/api/demo-data", methods=["POST"])
@require_api_key
def api_demo_data_load():
    conn = get_connection()
    try:
        if is_demo_data_loaded(conn):
            return jsonify({"error": "Demo data is already loaded. Clear it first."}), 409
        stats = load_demo_data_into_db(conn)
        return jsonify({"loaded": True, "stats": stats})
    finally:
        conn.close()


@app.route("/api/demo-data", methods=["DELETE"])
@require_api_key
def api_demo_data_clear():
    conn = get_connection()
    try:
        stats = clear_demo_data_from_db(conn)
        return jsonify({"loaded": False, "stats": stats})
    finally:
        conn.close()


@app.route("/api/demo-data/reset", methods=["POST"])
@require_api_key
def api_demo_data_reset():
    conn = get_connection()
    try:
        clear_demo_data_from_db(conn)
        data = build_all_demo_data()
        save_demo_data_to_files(data)
        stats = load_demo_data_into_db(conn)
        return jsonify({"loaded": True, "stats": stats})
    finally:
        conn.close()


@app.route("/api/demo-data/files")
def api_demo_data_files():
    data = load_demo_data_from_files()
    if not data["runs"]:
        data = build_all_demo_data()
        save_demo_data_to_files(data)
        data = load_demo_data_from_files()
    return jsonify(data)


@app.route("/api/demo-data/files", methods=["PUT"])
@require_api_key
def api_demo_data_files_update():
    body = flask_request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body is required"}), 400
    if "runs" not in body or not isinstance(body["runs"], list):
        return jsonify({"error": "'runs' array is required"}), 400
    save_demo_data_to_files(body)
    conn = get_connection()
    try:
        was_loaded = is_demo_data_loaded(conn)
        if was_loaded:
            clear_demo_data_from_db(conn)
            stats = load_demo_data_into_db(conn)
            return jsonify({"saved": True, "reloaded": True, "stats": stats})
        return jsonify({"saved": True, "reloaded": False})
    finally:
        conn.close()


AUDIT_LOG_DIR= pathlib.Path(__file__).resolve().parent.parent / "logs"


@app.route("/api/audit-log")
@require_api_key
def api_audit_log():
    page, per_page = _get_pagination()
    action_filter = flask_request.args.get("action", "")
    user_filter = flask_request.args.get("user", "")
    conn = get_connection()
    try:
        return jsonify(query_audit_logs(conn, page=page, per_page=per_page,
                                        action_filter=action_filter, user_filter=user_filter))
    finally:
        conn.close()


@app.route("/api/audit-log/export", methods=["POST"])
@require_api_key
def api_audit_log_export():
    body = flask_request.get_json(silent=True) or {}
    since = body.get("since", "")
    conn = get_connection()
    try:
        entries = export_audit_logs(conn, since=since)
        AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        export_path = AUDIT_LOG_DIR / f"audit-log-{ts}.json"
        with open(export_path, "w") as f:
            json.dump({"exported_at": ts, "since": since, "entries": entries}, f, indent=2)
            f.write("\n")
        _audit("export_audit_log", details=json.dumps({"file": str(export_path), "entries": len(entries)}))
        return jsonify({"file": str(export_path), "entries": len(entries)})
    finally:
        conn.close()


if __name__== "__main__":
    from dotenv import load_dotenv
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
