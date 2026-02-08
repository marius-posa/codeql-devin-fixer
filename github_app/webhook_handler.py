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
workflow_dispatch (custom)
    Manual scan trigger via the app's API.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Callable

log = logging.getLogger(__name__)


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
        log.debug("Ignoring unhandled event: %s", event_type)
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


_EVENT_HANDLERS: dict[str, Callable[..., dict]] = {
    "installation": handle_installation,
    "installation_repositories": handle_installation_repositories,
    "push": handle_push,
}
