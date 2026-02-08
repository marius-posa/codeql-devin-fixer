"""GitHub OAuth integration for the telemetry dashboard.

Provides login/callback/logout routes and helpers to fetch the
authenticated user's accessible repositories so the dashboard can
filter data accordingly.

Configuration (environment variables):
    GITHUB_CLIENT_ID      OAuth App client ID
    GITHUB_CLIENT_SECRET  OAuth App client secret
    FLASK_SECRET_KEY      Secret used for session cookies
"""

import os
import logging

import requests
from flask import (
    Blueprint,
    redirect,
    request as flask_request,
    session,
    url_for,
    jsonify,
)

log = logging.getLogger(__name__)

oauth_bp = Blueprint("oauth", __name__)

_GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_API = "https://api.github.com"


def _client_id() -> str:
    return os.environ.get("GITHUB_CLIENT_ID", "")


def _client_secret() -> str:
    return os.environ.get("GITHUB_CLIENT_SECRET", "")


def is_oauth_configured() -> bool:
    return bool(_client_id() and _client_secret())


def get_current_user() -> dict | None:
    return session.get("gh_user")


def get_user_repos() -> list[str]:
    return session.get("gh_repos", [])


def _gh_get(url: str, token: str, params: dict | None = None) -> requests.Response:
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    return requests.get(url, headers=headers, params=params or {}, timeout=15)


def _fetch_user_profile(token: str) -> dict:
    resp = _gh_get(f"{_GITHUB_API}/user", token)
    resp.raise_for_status()
    data = resp.json()
    return {
        "login": data["login"],
        "name": data.get("name") or data["login"],
        "avatar_url": data.get("avatar_url", ""),
        "html_url": data.get("html_url", ""),
    }


def _fetch_user_repos(token: str) -> list[str]:
    repos: list[str] = []
    page = 1
    while True:
        resp = _gh_get(
            f"{_GITHUB_API}/user/repos",
            token,
            params={"per_page": 100, "page": page, "sort": "full_name"},
        )
        if resp.status_code != 200:
            break
        items = resp.json()
        if not items:
            break
        for r in items:
            repos.append(r["html_url"])
        if len(items) < 100:
            break
        page += 1
    return repos


def _fetch_user_orgs(token: str) -> list[str]:
    resp = _gh_get(f"{_GITHUB_API}/user/orgs", token, params={"per_page": 100})
    if resp.status_code != 200:
        return []
    return [o["login"] for o in resp.json()]


def filter_by_user_access(items: list[dict], repo_key: str = "target_repo") -> list[dict]:
    user = get_current_user()
    if not user or not is_oauth_configured():
        return items
    allowed = get_user_repos()
    if not allowed:
        return items
    allowed_set = set(allowed)
    return [
        item for item in items
        if item.get(repo_key, "") in allowed_set
    ]


@oauth_bp.route("/login")
def login():
    if not is_oauth_configured():
        return jsonify({"error": "OAuth not configured"}), 400
    scope = "read:org,repo"
    callback = url_for("oauth.callback", _external=True)
    return redirect(
        f"{_GITHUB_AUTHORIZE_URL}?client_id={_client_id()}"
        f"&redirect_uri={callback}&scope={scope}"
    )


@oauth_bp.route("/callback")
def callback():
    code = flask_request.args.get("code")
    if not code:
        return redirect(url_for("index"))

    resp = requests.post(
        _GITHUB_TOKEN_URL,
        json={
            "client_id": _client_id(),
            "client_secret": _client_secret(),
            "code": code,
        },
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if resp.status_code != 200:
        log.warning("OAuth token exchange failed: %s", resp.status_code)
        return redirect(url_for("index"))

    token_data = resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        log.warning("No access_token in OAuth response")
        return redirect(url_for("index"))

    try:
        user = _fetch_user_profile(access_token)
        repos = _fetch_user_repos(access_token)
        orgs = _fetch_user_orgs(access_token)
    except Exception:
        log.exception("Failed to fetch user data from GitHub")
        return redirect(url_for("index"))

    session["gh_user"] = user
    session["gh_repos"] = repos
    session["gh_orgs"] = orgs
    session["gh_token"] = access_token

    return redirect(url_for("index"))


@oauth_bp.route("/logout")
def logout():
    session.pop("gh_user", None)
    session.pop("gh_repos", None)
    session.pop("gh_orgs", None)
    session.pop("gh_token", None)
    return redirect(url_for("index"))


@oauth_bp.route("/api/me")
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({"logged_in": False, "oauth_configured": is_oauth_configured()})
    return jsonify({
        "logged_in": True,
        "oauth_configured": True,
        "user": user,
        "orgs": session.get("gh_orgs", []),
        "repo_count": len(get_user_repos()),
    })
