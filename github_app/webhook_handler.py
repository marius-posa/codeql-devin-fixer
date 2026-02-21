"""GitHub webhook event processing for the CodeQL Devin Fixer App.

Handles incoming webhook events from GitHub and routes them to the
appropriate handlers.  All payloads are verified via HMAC-SHA256 before
processing.

Supported events
----------------
installation / installation_repositories
    When the app is installed or repos are added/removed.
push
    When code is pushed to a repo where the app is installed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import pathlib
from typing import Callable

log = logging.getLogger(__name__)

_ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
REGISTRY_PATH = _ROOT_DIR / "repo_registry.json"


def verify_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    if not signature or not secret:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def route_event(event_type: str, payload: dict) -> dict:
    handler = _EVENT_HANDLERS.get(event_type)
    if handler is None:
        safe_event = str(event_type).replace("\n", "").replace("\r", "")
        log.debug("Ignoring unhandled event: %s", safe_event)
        return {"status": "ignored", "event": event_type}
    return handler(payload)


def handle_installation(payload: dict) -> dict:
    action = payload.get("action", "")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    account = installation.get("account", {})
    login = account.get("login", "")

    if action == "created":
        repos = payload.get("repositories", [])
        repo_names = [r.get("full_name", "") for r in repos]
        log.info(
            "App installed by %s (installation %s) on %d repo(s): %s",
            login, installation_id, len(repos), ", ".join(repo_names[:5]),
        )
        _update_registry_installation_id(installation_id, repo_names)
        return {
            "status": "installed",
            "installation_id": installation_id,
            "account": login,
            "repositories": repo_names,
        }

    if action == "deleted":
        log.info("App uninstalled by %s (installation %s)", login, installation_id)
        return {
            "status": "uninstalled",
            "installation_id": installation_id,
            "account": login,
        }

    if action == "suspend":
        log.info("App suspended by %s (installation %s)", login, installation_id)
        return {"status": "suspended", "installation_id": installation_id}

    if action == "unsuspend":
        log.info("App unsuspended by %s (installation %s)", login, installation_id)
        return {"status": "unsuspended", "installation_id": installation_id}

    return {"status": "ignored", "action": action}


def handle_installation_repositories(payload: dict) -> dict:
    action = payload.get("action", "")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")

    if action == "added":
        added = payload.get("repositories_added", [])
        repo_names = [r.get("full_name", "") for r in added]
        log.info(
            "Repos added to installation %s: %s",
            installation_id, ", ".join(repo_names),
        )
        _update_registry_installation_id(installation_id, repo_names)
        return {
            "status": "repos_added",
            "installation_id": installation_id,
            "repositories": repo_names,
        }

    if action == "removed":
        removed = payload.get("repositories_removed", [])
        repo_names = [r.get("full_name", "") for r in removed]
        log.info(
            "Repos removed from installation %s: %s",
            installation_id, ", ".join(repo_names),
        )
        return {
            "status": "repos_removed",
            "installation_id": installation_id,
            "repositories": repo_names,
        }

    return {"status": "ignored", "action": action}


def handle_push(payload: dict) -> dict:
    repo = payload.get("repository", {})
    full_name = repo.get("full_name", "")
    ref = payload.get("ref", "")
    default_branch = repo.get("default_branch", "main")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")

    if ref != f"refs/heads/{default_branch}":
        log.debug(
            "Ignoring push to non-default branch %s on %s", ref, full_name,
        )
        return {"status": "ignored", "reason": "non-default branch"}

    pusher = payload.get("pusher", {}).get("name", "unknown")
    commits = payload.get("commits", [])
    log.info(
        "Push to %s by %s (%d commit(s)) - eligible for scan",
        full_name, pusher, len(commits),
    )

    return {
        "status": "scan_eligible",
        "installation_id": installation_id,
        "repository": full_name,
        "ref": ref,
        "default_branch": default_branch,
        "pusher": pusher,
        "commit_count": len(commits),
    }


def _update_registry_installation_id(
    installation_id: int | None,
    repo_names: list[str],
) -> None:
    """Store the GitHub App installation_id for repos in the registry."""
    if not installation_id or not repo_names:
        return
    if not REGISTRY_PATH.exists():
        return
    try:
        with open(REGISTRY_PATH) as f:
            registry = json.load(f)
    except (json.JSONDecodeError, OSError):
        return

    changed = False
    full_urls = {f"https://github.com/{name}" for name in repo_names}
    for repo_entry in registry.get("repos", []):
        repo_url = repo_entry.get("repo", "")
        owner_repo = repo_url.replace("https://github.com/", "")
        if repo_url in full_urls or owner_repo in repo_names:
            if repo_entry.get("installation_id") != installation_id:
                repo_entry["installation_id"] = installation_id
                changed = True

    if changed:
        try:
            with open(REGISTRY_PATH, "w") as f:
                json.dump(registry, f, indent=2)
                f.write("\n")
            log.info(
                "Updated installation_id=%s for %d repo(s) in registry",
                installation_id, len(repo_names),
            )
        except OSError as exc:
            log.warning("Failed to update registry: %s", exc)


_EVENT_HANDLERS: dict[str, Callable[..., dict]] = {
    "installation": handle_installation,
    "installation_repositories": handle_installation_repositories,
    "push": handle_push,
}
