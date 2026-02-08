"""Flask server for the CodeQL Devin Fixer GitHub App.

Exposes a webhook endpoint for GitHub events and API endpoints for
managing installations and triggering scans.  Designed to run alongside
(or integrated with) the existing telemetry dashboard.

Endpoints
---------
POST /api/github/webhook
    Receives GitHub webhook events (installation, push, etc.).
POST /api/github/scan
    Manually trigger a scan for a specific repo.
GET  /api/github/installations
    List all app installations.
GET  /api/github/installations/<id>/repos
    List repos for an installation.
GET  /healthz
    Health check.
"""

from __future__ import annotations

import logging
import os
import pathlib
import sys

from flask import Flask, jsonify, request as flask_request

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from github_app.auth import GitHubAppAuth
from github_app.webhook_handler import verify_signature, route_event
from github_app.config import AppConfig
from github_app.scan_trigger import trigger_scan

log = logging.getLogger(__name__)


def create_app(config: AppConfig | None = None) -> Flask:
    if config is None:
        config = AppConfig.from_env()

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    app = Flask(__name__)
    app.config["APP_CONFIG"] = config

    auth = GitHubAppAuth.from_key_file(config.app_id, config.private_key_path)
    app.config["APP_AUTH"] = auth

    @app.route("/healthz")
    def healthz():
        try:
            info = auth.get_app_info()
            return jsonify({
                "status": "ok",
                "app_name": info.get("name", ""),
                "app_id": config.app_id,
            })
        except Exception as exc:
            log.error("Health check failed: %s", exc)
            return jsonify({"status": "error", "detail": str(exc)}), 503

    @app.route("/api/github/webhook", methods=["POST"])
    def webhook():
        signature = flask_request.headers.get("X-Hub-Signature-256", "")
        if not verify_signature(
            flask_request.get_data(), signature, config.webhook_secret,
        ):
            return jsonify({"error": "Invalid signature"}), 401

        event_type = flask_request.headers.get("X-GitHub-Event", "")
        delivery_id = flask_request.headers.get("X-GitHub-Delivery", "")
        payload = flask_request.get_json(silent=True) or {}

        log.info("Webhook: event=%s delivery=%s", event_type, delivery_id)

        result = route_event(event_type, payload)

        if result.get("status") == "scan_eligible":
            _maybe_trigger_scan(config, auth, result)

        return jsonify(result)

    @app.route("/api/github/scan", methods=["POST"])
    def manual_scan():
        body = flask_request.get_json(silent=True) or {}
        repo = body.get("repository", "")
        installation_id = body.get("installation_id")

        if not repo:
            return jsonify({"error": "repository is required"}), 400
        if not installation_id:
            return jsonify({"error": "installation_id is required"}), 400

        try:
            token = auth.get_installation_token(int(installation_id))
        except Exception as exc:
            return jsonify({"error": f"Token error: {exc}"}), 400

        scan_config = {
            "target_repo": f"https://github.com/{repo}",
            "github_token": token,
            "devin_api_key": config.devin_api_key,
            "batch_size": body.get("batch_size", config.default_batch_size),
            "max_sessions": body.get("max_sessions", config.default_max_sessions),
            "severity_threshold": body.get(
                "severity_threshold", config.default_severity_threshold,
            ),
            "queries": body.get("queries", config.default_queries),
            "default_branch": body.get("default_branch", config.default_branch),
            "dry_run": body.get("dry_run", False),
        }

        result = trigger_scan(scan_config)
        return jsonify(result)

    @app.route("/api/github/installations")
    def list_installations():
        try:
            installations = auth.list_installations()
            return jsonify({
                "installations": [
                    {
                        "id": inst.get("id"),
                        "account": inst.get("account", {}).get("login", ""),
                        "account_type": inst.get("account", {}).get("type", ""),
                        "target_type": inst.get("target_type", ""),
                        "created_at": inst.get("created_at", ""),
                        "app_slug": inst.get("app_slug", ""),
                    }
                    for inst in installations
                ],
                "total": len(installations),
            })
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/github/installations/<int:installation_id>/repos")
    def installation_repos(installation_id: int):
        try:
            repos = auth.get_installation_repos(installation_id)
            return jsonify({
                "repositories": [
                    {
                        "full_name": r.get("full_name", ""),
                        "private": r.get("private", False),
                        "default_branch": r.get("default_branch", "main"),
                        "language": r.get("language", ""),
                        "html_url": r.get("html_url", ""),
                    }
                    for r in repos
                ],
                "total": len(repos),
            })
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return app


def _maybe_trigger_scan(
    config: AppConfig, auth: GitHubAppAuth, event_result: dict,
) -> None:
    installation_id = event_result.get("installation_id")
    repo = event_result.get("repository", "")
    default_branch = event_result.get("default_branch", config.default_branch)

    if not installation_id or not repo:
        return

    try:
        token = auth.get_installation_token(installation_id)
    except Exception as exc:
        log.error("Failed to get token for installation %s: %s", installation_id, exc)
        return

    scan_config = {
        "target_repo": f"https://github.com/{repo}",
        "github_token": token,
        "devin_api_key": config.devin_api_key,
        "batch_size": config.default_batch_size,
        "max_sessions": config.default_max_sessions,
        "severity_threshold": config.default_severity_threshold,
        "queries": config.default_queries,
        "default_branch": default_branch,
        "dry_run": False,
    }

    log.info("Auto-triggering scan for %s (installation %s)", repo, installation_id)
    trigger_scan(scan_config)
