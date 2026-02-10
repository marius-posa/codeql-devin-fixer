#!/usr/bin/env python3
"""Shared Devin API utilities used by knowledge.py, retry_feedback.py, and dispatch_devin.py."""

import requests

try:
    from logging_config import setup_logging
except ImportError:
    from scripts.logging_config import setup_logging

try:
    from retry_utils import request_with_retry as _retry_request
except ImportError:
    from scripts.retry_utils import request_with_retry as _retry_request

logger = setup_logging(__name__)

DEVIN_API_BASE = "https://api.devin.ai/v1"

TERMINAL_STATUSES = frozenset(
    {"finished", "blocked", "expired", "failed", "cancelled",
     "stopped", "error"}
)


def clean_session_id(session_id: str) -> str:
    """Strip the ``devin-`` prefix from a session ID if present."""
    if session_id.startswith("devin-"):
        return session_id[len("devin-"):]
    return session_id


def headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def request_with_retry(
    method: str,
    url: str,
    api_key: str,
    json_data: dict | None = None,
) -> dict:
    """Devin-API-specific retry wrapper.

    Delegates to :func:`retry_utils.request_with_retry` (exponential
    backoff with jitter) and returns parsed JSON.
    """
    resp = _retry_request(
        method,
        url,
        headers=headers(api_key),
        json=json_data,
        timeout=30,
    )
    resp.raise_for_status()
    if resp.status_code == 204:
        return {}
    return resp.json()


def upload_attachment(api_key: str, file_path: str) -> str:
    """Upload a file to the Devin Attachments API and return the file URL.

    Uses ``POST /v1/attachments`` with multipart form data.  The returned
    URL can be referenced in session prompts via ``ATTACHMENT:"<url>"``.

    Returns an empty string if the upload fails so callers can fall back
    to inline embedding.
    """
    try:
        with open(file_path, "rb") as fh:
            resp = requests.post(
                f"{DEVIN_API_BASE}/attachments",
                headers={"Authorization": f"Bearer {api_key}"},
                files={"file": fh},
                timeout=60,
            )
            resp.raise_for_status()
            return resp.text.strip().strip('"')
    except (OSError, requests.exceptions.RequestException) as exc:
        logger.warning("Attachment upload failed for %s: %s", file_path, exc)
        return ""


def fetch_pr_diff(pr_url: str, github_token: str = "") -> str:
    if not pr_url or "github.com" not in pr_url:
        return ""

    parts = pr_url.rstrip("/").split("/")
    try:
        idx = parts.index("pull")
        owner = parts[idx - 2]
        repo = parts[idx - 1]
        pr_number = parts[idx + 1]
    except (ValueError, IndexError):
        return ""

    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    req_headers: dict[str, str] = {"Accept": "application/vnd.github.v3.diff"}
    if github_token:
        req_headers["Authorization"] = f"Bearer {github_token}"

    try:
        resp = _retry_request("GET", api_url, headers=req_headers, timeout=30)
        resp.raise_for_status()
        diff_text = resp.text
        if len(diff_text) > 8000:
            diff_text = diff_text[:8000] + "\n... (diff truncated)"
        return diff_text
    except requests.exceptions.RequestException as e:
        logger.warning("Failed to fetch PR diff from %s: %s", pr_url, e)
        return ""
