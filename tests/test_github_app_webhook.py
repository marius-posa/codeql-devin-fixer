"""Unit tests for github_app/webhook_handler.py.

Covers: signature verification, event routing, handler logic.
"""

import hashlib
import hmac
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from github_app.webhook_handler import (
    verify_signature,
    route_event,
    handle_installation,
    handle_installation_repositories,
    handle_push,
)


class TestVerifySignature:
    def test_valid_signature(self):
        payload = b'{"action": "created"}'
        secret = "test-secret"
        sig = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert verify_signature(payload, sig, secret) is True

    def test_invalid_signature(self):
        payload = b'{"action": "created"}'
        assert verify_signature(payload, "sha256=bad", "secret") is False

    def test_empty_signature(self):
        assert verify_signature(b"data", "", "secret") is False

    def test_empty_secret(self):
        assert verify_signature(b"data", "sha256=abc", "") is False

    def test_tampered_payload(self):
        secret = "mysecret"
        original = b"original"
        sig = "sha256=" + hmac.new(
            secret.encode(), original, hashlib.sha256
        ).hexdigest()
        assert verify_signature(b"tampered", sig, secret) is False


class TestRouteEvent:
    def test_routes_installation_event(self):
        payload = {
            "action": "created",
            "installation": {"id": 1, "account": {"login": "user1"}},
            "repositories": [{"full_name": "user1/repo1"}],
        }
        result = route_event("installation", payload)
        assert result["status"] == "installed"

    def test_routes_push_event(self):
        payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "user1/repo1", "default_branch": "main"},
            "installation": {"id": 1},
            "pusher": {"name": "user1"},
            "commits": [{"id": "abc123"}],
        }
        result = route_event("push", payload)
        assert result["status"] == "scan_eligible"

    def test_ignores_unknown_event(self):
        result = route_event("star", {"action": "created"})
        assert result["status"] == "ignored"

    def test_routes_installation_repositories(self):
        payload = {
            "action": "added",
            "installation": {"id": 1},
            "repositories_added": [{"full_name": "user1/new-repo"}],
        }
        result = route_event("installation_repositories", payload)
        assert result["status"] == "repos_added"


class TestHandleInstallation:
    def test_created(self):
        payload = {
            "action": "created",
            "installation": {"id": 42, "account": {"login": "testuser"}},
            "repositories": [
                {"full_name": "testuser/repo1"},
                {"full_name": "testuser/repo2"},
            ],
        }
        result = handle_installation(payload)
        assert result["status"] == "installed"
        assert result["installation_id"] == 42
        assert result["account"] == "testuser"
        assert len(result["repositories"]) == 2

    def test_deleted(self):
        payload = {
            "action": "deleted",
            "installation": {"id": 42, "account": {"login": "testuser"}},
        }
        result = handle_installation(payload)
        assert result["status"] == "uninstalled"
        assert result["installation_id"] == 42

    def test_suspend(self):
        payload = {
            "action": "suspend",
            "installation": {"id": 42, "account": {"login": "testuser"}},
        }
        result = handle_installation(payload)
        assert result["status"] == "suspended"

    def test_unsuspend(self):
        payload = {
            "action": "unsuspend",
            "installation": {"id": 42, "account": {"login": "testuser"}},
        }
        result = handle_installation(payload)
        assert result["status"] == "unsuspended"

    def test_unknown_action(self):
        payload = {
            "action": "new_permissions_accepted",
            "installation": {"id": 42, "account": {"login": "testuser"}},
        }
        result = handle_installation(payload)
        assert result["status"] == "ignored"


class TestHandleInstallationRepositories:
    def test_repos_added(self):
        payload = {
            "action": "added",
            "installation": {"id": 10},
            "repositories_added": [
                {"full_name": "org/repo-a"},
                {"full_name": "org/repo-b"},
            ],
        }
        result = handle_installation_repositories(payload)
        assert result["status"] == "repos_added"
        assert "org/repo-a" in result["repositories"]
        assert "org/repo-b" in result["repositories"]

    def test_repos_removed(self):
        payload = {
            "action": "removed",
            "installation": {"id": 10},
            "repositories_removed": [{"full_name": "org/old-repo"}],
        }
        result = handle_installation_repositories(payload)
        assert result["status"] == "repos_removed"
        assert "org/old-repo" in result["repositories"]


class TestHandlePush:
    def test_push_to_default_branch(self):
        payload = {
            "ref": "refs/heads/main",
            "repository": {
                "full_name": "user/repo",
                "default_branch": "main",
            },
            "installation": {"id": 5},
            "pusher": {"name": "dev"},
            "commits": [{"id": "a"}, {"id": "b"}],
        }
        result = handle_push(payload)
        assert result["status"] == "scan_eligible"
        assert result["repository"] == "user/repo"
        assert result["commit_count"] == 2

    def test_push_to_non_default_branch_ignored(self):
        payload = {
            "ref": "refs/heads/feature-branch",
            "repository": {
                "full_name": "user/repo",
                "default_branch": "main",
            },
            "installation": {"id": 5},
            "pusher": {"name": "dev"},
            "commits": [],
        }
        result = handle_push(payload)
        assert result["status"] == "ignored"

    def test_push_to_master_default(self):
        payload = {
            "ref": "refs/heads/master",
            "repository": {
                "full_name": "user/repo",
                "default_branch": "master",
            },
            "installation": {"id": 5},
            "pusher": {"name": "dev"},
            "commits": [{"id": "x"}],
        }
        result = handle_push(payload)
        assert result["status"] == "scan_eligible"
