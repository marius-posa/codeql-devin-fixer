#!/usr/bin/env python3
"""Shared Devin API utilities used by knowledge.py, retry_feedback.py, and dispatch_devin.py."""

import logging
import time

import requests

logger = logging.getLogger(__name__)

DEVIN_API_BASE = "https://api.devin.ai/v1"

MAX_RETRIES = 3
RETRY_DELAY = 5

TERMINAL_STATUSES = frozenset(
    {"finished", "blocked", "expired", "failed", "canceled", "cancelled"}
)


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
    last_err: requests.exceptions.RequestException | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(
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
        except requests.exceptions.RequestException as e:
            last_err = e
            if attempt < MAX_RETRIES:
                logger.warning("Retry %d/%d after error: %s", attempt, MAX_RETRIES, e)
                time.sleep(RETRY_DELAY * attempt)
    raise last_err  # type: ignore[misc]


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
        resp = requests.get(api_url, headers=req_headers, timeout=30)
        resp.raise_for_status()
        diff_text = resp.text
        if len(diff_text) > 8000:
            diff_text = diff_text[:8000] + "\n... (diff truncated)"
        return diff_text
    except requests.exceptions.RequestException as e:
        logger.warning("Failed to fetch PR diff from %s: %s", pr_url, e)
        return ""
