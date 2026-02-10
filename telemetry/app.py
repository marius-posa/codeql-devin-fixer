#!/usr/bin/env python3
"""Centralized telemetry server for CodeQL Devin Fixer.

Aggregates data from all action runs across every target repository into a
single dashboard.  Run data is stored in a SQLite database (migrated from
JSON files under ``telemetry/runs/``).

Route handlers are organized into Flask Blueprints under the ``routes/``
package:

* **api** -- core read endpoints, polling, dispatch, and audit log
* **orchestrator** -- orchestrator plan/dispatch/cycle/config endpoints
* **registry** -- repository registry CRUD
* **demo** -- demo data management
"""

import os
import pathlib

from flask import Flask, request as flask_request
from flask_cors import CORS
from cachelib import FileSystemCache
from flask_session import Session

from config import RUNS_DIR
from migrate_json_to_sqlite import ensure_db_populated
from oauth import oauth_bp
from routes import api_bp, orchestrator_bp, registry_bp, demo_bp

SAMPLE_DATA_DIR = pathlib.Path(__file__).parent / "sample_data"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

_SESSION_DIR = pathlib.Path(__file__).parent / "flask_session"
_SESSION_DIR.mkdir(parents=True, exist_ok=True)
app.config["SESSION_TYPE"] = "cachelib"
app.config["SESSION_CACHELIB"] = FileSystemCache(str(_SESSION_DIR), threshold=500)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
Session(app)

_cors_raw = os.environ.get("CORS_ORIGINS", "")
_cors_origins: list[str] | str = (
    [o.strip() for o in _cors_raw.split(",") if o.strip()]
    if _cors_raw
    else ["http://localhost:5000", "http://127.0.0.1:5000"]
)
CORS(app, origins=_cors_origins, supports_credentials=True)

from extensions import limiter
limiter.init_app(app)

app.register_blueprint(oauth_bp)
app.register_blueprint(api_bp)
app.register_blueprint(orchestrator_bp)
app.register_blueprint(registry_bp)
app.register_blueprint(demo_bp)

ensure_db_populated(RUNS_DIR, SAMPLE_DATA_DIR)


def _track_issues_across_runs(runs: list[dict]) -> list[dict]:
    """In-memory cross-run issue tracker (kept for backward compatibility).

    Accepts a list of run dicts (each with ``issue_fingerprints``) and returns
    the same aggregated structure that ``query_issues()`` produces, but computed
    entirely in memory without touching the database.
    """
    from issue_tracking import compute_sla_status, _parse_ts

    fp_history: dict[str, list[dict]] = {}
    fp_metadata: dict[str, dict] = {}
    runs_sorted = sorted(runs, key=lambda r: r.get("timestamp", ""))
    runs_per_repo: dict[str, int] = {}
    runs_with_fps_per_repo: dict[str, int] = {}

    for run in runs_sorted:
        repo = run.get("target_repo", "")
        runs_per_repo[repo] = runs_per_repo.get(repo, 0) + 1
        fps_list = run.get("issue_fingerprints", [])
        if fps_list:
            runs_with_fps_per_repo[repo] = runs_with_fps_per_repo.get(repo, 0) + 1
        for iss in fps_list:
            fp = iss.get("fingerprint", "")
            if not fp:
                continue
            if fp not in fp_history:
                fp_history[fp] = []
            fp_history[fp].append({
                "run_number": run.get("run_number", 0),
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

    latest_run_per_repo: dict[str, int] = {}
    for run in runs_sorted:
        repo = run.get("target_repo", "")
        latest_run_per_repo[repo] = run.get("run_number", 0)

    latest_fps: set[str] = set()
    for run in runs_sorted:
        repo = run.get("target_repo", "")
        if run.get("run_number", 0) == latest_run_per_repo.get(repo):
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

        fix_duration_hours = None
        if status == "fixed":
            first_ts = _parse_ts(first["timestamp"])
            latest_ts = _parse_ts(latest["timestamp"])
            if first_ts and latest_ts:
                delta = latest_ts - first_ts
                fix_duration_hours = round(delta.total_seconds() / 3600, 1)

        found_at_ts = _parse_ts(first["timestamp"])
        fixed_at_ts = _parse_ts(latest["timestamp"]) if status == "fixed" else None
        sla = compute_sla_status(
            meta.get("severity_tier", ""), found_at_ts, fixed_at_ts,
        )

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
            "fix_duration_hours": fix_duration_hours,
            "found_at": first["timestamp"],
            "fixed_at": latest["timestamp"] if status == "fixed" else None,
            "sla_status": sla["sla_status"],
            "sla_limit_hours": sla["sla_limit_hours"],
            "sla_hours_elapsed": sla["sla_hours_elapsed"],
            "sla_hours_remaining": sla["sla_hours_remaining"],
        })

    _STATUS_ORDER = {"recurring": 0, "new": 1, "fixed": 2}
    result.sort(key=lambda x: (
        _STATUS_ORDER.get(x["status"], 3),
        x.get("last_seen_date", ""),
    ))
    return result


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://avatars.githubusercontent.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if flask_request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


if __name__ == "__main__":
    from dotenv import load_dotenv
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
