"""Core API blueprint -- read endpoints, polling, dispatch, and audit log."""

import io
import json
import os
import pathlib

import requests
from flask import Blueprint, jsonify, render_template, request as flask_request, send_file

from config import RUNS_DIR, gh_headers

try:
    from devin_api import clean_session_id
except ImportError:
    from scripts.devin_api import clean_session_id

from database import (
    db_connection,
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
    query_issue_detail,
    update_issue_status,
    query_dispatch_impact,
    search_issues,
    refresh_fingerprint_issues,
    backfill_pr_urls,
    query_audit_logs,
    export_audit_logs,
)
from github_service import fetch_prs_from_github_to_db, link_prs_to_sessions_db
from devin_service import poll_devin_sessions_db
from aggregation import compute_sla_summary
from verification import (
    load_verification_records,
    build_session_verification_map,
    build_fingerprint_fix_map,
    aggregate_verification_stats,
)
from oauth import is_oauth_configured, get_current_user, filter_by_user_access
from pdf_report import generate_pdf
from helpers import (
    require_api_key,
    _get_telemetry_api_key,
    _is_authenticated,
    _audit,
    _paginate,
    _get_pagination,
)
from extensions import limiter

api_bp = Blueprint("api", __name__)

AUDIT_LOG_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "logs"


@api_bp.route("/")
def index():
    return render_template("dashboard.html")


@api_bp.route("/repo/<path:repo_url>")
def repo_page(repo_url):
    full_url = "https://github.com/" + repo_url
    return render_template("repo.html", repo_url=full_url, repo_short=repo_url)


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
        clean = clean_session_id(sid)
        if clean in pr_by_session:
            s["pr_url"] = pr_by_session[clean]
            continue
        for iid in s.get("issue_ids", []):
            if iid in pr_by_issue:
                s["pr_url"] = pr_by_issue[iid]
                break


@api_bp.route("/api/repo/<path:repo_url>")
def api_repo_detail(repo_url):
    full_url = "https://github.com/" + repo_url
    with db_connection() as conn:
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


@api_bp.route("/api/runs")
def api_runs():
    page, per_page = _get_pagination()
    with db_connection() as conn:
        return jsonify(query_runs(conn, page=page, per_page=per_page))


@api_bp.route("/api/sessions")
def api_sessions():
    page, per_page = _get_pagination()
    with db_connection() as conn:
        result = query_sessions(conn, page=page, per_page=per_page)
        all_prs = query_all_prs(conn)
        _link_prs_to_session_items(result["items"], all_prs)
        return jsonify(result)


@api_bp.route("/api/prs")
def api_prs():
    page, per_page = _get_pagination()
    with db_connection() as conn:
        return jsonify(query_prs(conn, page=page, per_page=per_page))


@api_bp.route("/api/stats")
def api_stats():
    period = flask_request.args.get("period", "all")
    with db_connection() as conn:
        result = query_stats(conn, period=period)
        result["period"] = period
        return jsonify(result)


@api_bp.route("/api/repos")
def api_repos():
    with db_connection() as conn:
        return jsonify(query_repos(conn))


@api_bp.route("/api/poll", methods=["POST"])
@require_api_key
def api_poll():
    with db_connection() as conn:
        sessions = query_all_sessions(conn)
        updated, poll_stats = poll_devin_sessions_db(conn, sessions)
        conn.commit()
        prs_count = fetch_prs_from_github_to_db(conn)
        conn.commit()
        link_prs_to_sessions_db(conn)
        conn.commit()
        _audit("poll_sessions", details=json.dumps({
            "polled": poll_stats["polled"],
            "skipped_terminal": poll_stats["skipped_terminal"],
            "errors": len(poll_stats["errors"]),
            "prs_found": prs_count,
        }))
        result: dict = {
            "sessions": updated,
            "polled": poll_stats["polled"],
            "skipped_terminal": poll_stats["skipped_terminal"],
            "prs_found": prs_count,
        }
        if poll_stats["errors"]:
            result["errors"] = poll_stats["errors"]
        return jsonify(result)


@api_bp.route("/api/poll-prs", methods=["POST"])
@require_api_key
def api_poll_prs():
    with db_connection() as conn:
        prs_count = fetch_prs_from_github_to_db(conn)
        conn.commit()
        all_prs = query_all_prs(conn)
        _audit("poll_prs", details=json.dumps({"prs_found": prs_count}))
        return jsonify({"prs": all_prs, "total": prs_count})


@api_bp.route("/api/refresh", methods=["POST"])
@require_api_key
def api_refresh():
    token = os.environ.get("GITHUB_TOKEN", "")
    action_repo = os.environ.get("ACTION_REPO", "")
    if not token or not action_repo:
        return jsonify({"error": "GITHUB_TOKEN and ACTION_REPO required"}), 400

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    with db_connection() as conn:
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
        if downloaded > 0:
            refresh_fingerprint_issues(conn)
            conn.commit()

        total_files = len(list(RUNS_DIR.glob("*.json")))
        _audit("refresh_runs", details=json.dumps({"downloaded": downloaded, "total_files": total_files}))
        return jsonify({
            "downloaded": downloaded,
            "total_files": total_files,
            "prs_found": prs_count,
        })


@api_bp.route("/api/config")
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


@api_bp.route("/api/report/pdf")
def api_report_pdf():
    with db_connection() as conn:
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


@api_bp.route("/api/backfill", methods=["POST"])
@require_api_key
def api_backfill():
    with db_connection() as conn:
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


@api_bp.route("/api/issues")
def api_issues():
    with db_connection() as conn:
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


@api_bp.route("/api/issues/<fingerprint>/detail")
def api_issue_detail(fingerprint):
    with db_connection() as conn:
        detail = query_issue_detail(conn, fingerprint)
        if detail is None:
            return jsonify({"error": "Issue not found"}), 404
        return jsonify(detail)


@api_bp.route("/api/issues/<fingerprint>/status", methods=["PATCH"])
@require_api_key
def api_issue_status(fingerprint):
    body = flask_request.get_json(silent=True) or {}
    new_status = body.get("status", "")
    if not new_status:
        return jsonify({"error": "status is required"}), 400
    with db_connection() as conn:
        ok = update_issue_status(conn, fingerprint, new_status)
        if not ok:
            return jsonify({"error": "Invalid status or issue not found"}), 400
        conn.commit()
        _audit("update_issue_status", resource=fingerprint, details=json.dumps({"status": new_status}))
        return jsonify({"success": True, "fingerprint": fingerprint, "status": new_status})


@api_bp.route("/api/dispatch/impact")
def api_dispatch_impact():
    target_repo = flask_request.args.get("target_repo", "")
    if not target_repo:
        return jsonify({"error": "target_repo is required"}), 400
    with db_connection() as conn:
        return jsonify(query_dispatch_impact(conn, target_repo))


@api_bp.route("/api/issues/search")
def api_issues_search():
    q = flask_request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "q parameter is required"}), 400
    repo_filter = flask_request.args.get("repo", "")
    with db_connection() as conn:
        results = search_issues(conn, q, target_repo=repo_filter)
        page, per_page = _get_pagination()
        return jsonify(_paginate(results, page, per_page))


@api_bp.route("/api/sla")
def api_sla():
    with db_connection() as conn:
        repo_filter = flask_request.args.get("repo", "")
        issues = query_issues(conn, target_repo=repo_filter)
        return jsonify(compute_sla_summary(issues))


@api_bp.route("/api/verification")
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


@api_bp.route("/api/dispatch/preflight")
def api_dispatch_preflight():
    target_repo = flask_request.args.get("target_repo", "")
    if not target_repo:
        return jsonify({"error": "target_repo is required"}), 400

    with db_connection() as conn:
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


@api_bp.route("/api/dispatch", methods=["POST"])
@limiter.limit("10/minute")
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


@api_bp.route("/api/audit-log")
def api_audit_log():
    page, per_page = _get_pagination()
    action_filter = flask_request.args.get("action", "")
    user_filter = flask_request.args.get("user", "")
    with db_connection() as conn:
        return jsonify(query_audit_logs(conn, page=page, per_page=per_page,
                                        action_filter=action_filter, user_filter=user_filter))


@api_bp.route("/api/audit-log/export", methods=["POST"])
@require_api_key
def api_audit_log_export():
    body = flask_request.get_json(silent=True) or {}
    since = body.get("since", "")
    with db_connection() as conn:
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
