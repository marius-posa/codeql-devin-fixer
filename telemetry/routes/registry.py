"""Registry blueprint -- repository registry CRUD operations."""

import json
import pathlib

from flask import Blueprint, jsonify, request as flask_request

from helpers import require_api_key, _audit

registry_bp = Blueprint("registry", __name__)

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent.parent.parent / "repo_registry.json"

_VALID_IMPORTANCE = ("low", "medium", "high", "critical")
_VALID_SCHEDULE = ("hourly", "daily", "weekly", "monthly")


def _load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {"version": "2.0", "defaults": {}, "orchestrator": {}, "concurrency": {"max_parallel": 3, "delay_seconds": 30}, "repos": []}
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def _save_registry(data: dict) -> None:
    with open(REGISTRY_PATH, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


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


@registry_bp.route("/api/registry")
def api_registry():
    return jsonify(_load_registry())


@registry_bp.route("/api/registry", methods=["PUT"])
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


@registry_bp.route("/api/registry/repos", methods=["POST"])
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


@registry_bp.route("/api/registry/repos/<int:idx>", methods=["PUT"])
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


@registry_bp.route("/api/registry/repos", methods=["DELETE"])
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
