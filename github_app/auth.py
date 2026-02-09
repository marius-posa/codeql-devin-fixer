"""GitHub App authentication: JWT generation and installation token management.

A GitHub App authenticates in two stages:

1. **App-level JWT** -- signed with the app's RSA private key, valid for
   up to 10 minutes.  Used to call endpoints like ``GET /app/installations``.
2. **Installation token** -- obtained by exchanging the JWT for a
   short-lived token scoped to a specific installation.  Used for all
   repository operations (clone, create PR, push, etc.).

This module handles both stages and caches installation tokens until they
expire (with a 60-second safety margin).
"""

from __future__ import annotations

import time
import threading

import jwt
import requests


TOKEN_EXPIRY_MARGIN_SECONDS = 60
JWT_EXPIRY_SECONDS = 600
GITHUB_API_BASE = "https://api.github.com"


class GitHubAppAuth:
    def __init__(self, app_id: int, private_key: str) -> None:
        self._app_id = app_id
        self._private_key = private_key
        self._token_cache: dict[int, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_key_file(cls, app_id: int, key_path: str) -> GitHubAppAuth:
        with open(key_path) as f:
            private_key = f.read()
        return cls(app_id, private_key)

    def generate_jwt(self) -> str:
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + JWT_EXPIRY_SECONDS,
            "iss": str(self._app_id),
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    @staticmethod
    def _validate_installation_id(installation_id: object) -> int:
        if not isinstance(installation_id, int) or isinstance(installation_id, bool):
            raise ValueError(
                f"installation_id must be a positive integer, got {type(installation_id).__name__}"
            )
        if installation_id <= 0:
            raise ValueError(
                f"installation_id must be a positive integer, got {installation_id}"
            )
        return installation_id

    def get_installation_token(self, installation_id: int) -> str:
        safe_id = self._validate_installation_id(installation_id)

        with self._lock:
            cached = self._token_cache.get(safe_id)
            if cached:
                token, expires_at = cached
                if time.time() < expires_at - TOKEN_EXPIRY_MARGIN_SECONDS:
                    return token

        token_jwt = self.generate_jwt()
        resp = requests.post(
            f"{GITHUB_API_BASE}/app/installations/{safe_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {token_jwt}",
                "Accept": "application/vnd.github+json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        token = data["token"]
        expires_at_str = data.get("expires_at", "")

        if expires_at_str:
            from datetime import datetime
            expires_at = datetime.fromisoformat(
                expires_at_str.replace("Z", "+00:00")
            ).timestamp()
        else:
            expires_at = time.time() + 3600

        with self._lock:
            self._token_cache[safe_id] = (token, expires_at)

        return token

    def get_app_info(self) -> dict:
        token_jwt = self.generate_jwt()
        resp = requests.get(
            f"{GITHUB_API_BASE}/app",
            headers={
                "Authorization": f"Bearer {token_jwt}",
                "Accept": "application/vnd.github+json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def list_installations(self) -> list[dict]:
        token_jwt = self.generate_jwt()
        installations: list[dict] = []
        page = 1
        while True:
            resp = requests.get(
                f"{GITHUB_API_BASE}/app/installations",
                headers={
                    "Authorization": f"Bearer {token_jwt}",
                    "Accept": "application/vnd.github+json",
                },
                params={"per_page": 100, "page": page},
                timeout=30,
            )
            resp.raise_for_status()
            items = resp.json()
            if not items:
                break
            installations.extend(items)
            if len(items) < 100:
                break
            page += 1
        return installations

    def get_installation_repos(self, installation_id: int) -> list[dict]:
        self._validate_installation_id(installation_id)
        token = self.get_installation_token(installation_id)
        repos: list[dict] = []
        page = 1
        while True:
            resp = requests.get(
                f"{GITHUB_API_BASE}/installation/repositories",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                },
                params={"per_page": 100, "page": page},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("repositories", [])
            if not items:
                break
            repos.extend(items)
            if len(items) < 100:
                break
            page += 1
        return repos

    def invalidate_token(self, installation_id: int) -> None:
        safe_id = self._validate_installation_id(installation_id)
        with self._lock:
            self._token_cache.pop(safe_id, None)
