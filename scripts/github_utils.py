"""Shared GitHub API and URL utilities for the CodeQL Devin Fixer pipeline.

This module consolidates helper functions that were previously duplicated
across multiple scripts (``config.py``, ``generate_dashboard.py``,
``persist_telemetry.py``, ``fork_repo.py``, ``dispatch_devin.py``).

Having a single source of truth for these utilities prevents drift and
makes it easier to apply changes (e.g. adding retry logic) in one place.
"""

import re
import time
from typing import Any

import requests


MAX_GH_RETRIES = 3
_GH_RETRY_DELAY = 2


def gh_headers(token: str = "") -> dict[str, str]:
    """Return standard GitHub API request headers.

    Parameters
    ----------
    token : str
        A GitHub Personal Access Token.  When empty the ``Authorization``
        header is omitted (anonymous requests).
    """
    h: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def normalize_repo_url(url: str) -> str:
    """Normalise a repository reference to a canonical HTTPS URL.

    Accepts ``owner/repo`` shorthand, full HTTPS URLs, and URLs with a
    trailing ``.git`` suffix.  Returns a URL without trailing slashes or
    ``.git``.
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if not url.startswith("http://") and not url.startswith("https://"):
        if re.match(r"^[\w.-]+/[\w.-]+$", url):
            url = f"https://github.com/{url}"
    return url


def validate_repo_url(url: str) -> str:
    """Normalise *url* and warn if it doesn't look like a GitHub repo URL."""
    url = normalize_repo_url(url)
    pattern = r"^https://github\.com/[\w.-]+/[\w.-]+$"
    if not re.match(pattern, url):
        print(f"WARNING: repo URL may be invalid: {url}")
    return url


def parse_repo_url(url: str) -> tuple[str, str]:
    """Extract ``(owner, repo)`` from a GitHub URL or ``owner/repo`` shorthand."""
    url = normalize_repo_url(url)
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)", url)
    if not m:
        raise ValueError(f"Cannot parse repo URL: {url}")
    return m.group(1), m.group(2)


def gh_api_request(
    method: str,
    url: str,
    token: str,
    retries: int = MAX_GH_RETRIES,
    **kwargs: Any,
) -> requests.Response:
    """Make a GitHub API request with retry logic for transient failures.

    Retries on 5xx status codes and network errors using exponential
    back-off with jitter.
    """
    import random

    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.request(
                method,
                url,
                headers=gh_headers(token),
                timeout=kwargs.pop("timeout", 30),
                **kwargs,
            )
            if resp.status_code < 500:
                return resp
            last_err = requests.exceptions.HTTPError(
                f"GitHub API returned {resp.status_code}"
            )
        except requests.exceptions.RequestException as e:
            last_err = e

        if attempt < retries:
            delay = _GH_RETRY_DELAY * (2 ** (attempt - 1)) + random.uniform(0, 1)
            print(f"  GitHub API retry {attempt}/{retries} after error: {last_err}")
            time.sleep(delay)

    raise last_err  # type: ignore[misc]
