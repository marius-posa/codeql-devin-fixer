#!/usr/bin/env python3
"""Shared retry utilities for resilient HTTP and subprocess operations.

Provides exponential backoff with jitter for API calls across the pipeline.
This centralises retry logic that was previously absent or inconsistent
across ``fork_repo.py``, ``persist_logs.py``, ``persist_telemetry.py``,
``generate_dashboard.py``, and ``dispatch_devin.py``.
"""

import random
import subprocess
import time

import requests

MAX_RETRIES= 3
BASE_DELAY = 2.0
MAX_JITTER = 1.0


def exponential_backoff_delay(attempt: int, base: float = BASE_DELAY, max_jitter: float = MAX_JITTER) -> float:
    """Calculate delay with exponential backoff and random jitter.

    Formula: ``base * 2^attempt + uniform(0, max_jitter)``

    For *attempt* values 1, 2, 3 this produces approximate delays of
    4-5 s, 8-9 s, 16-17 s -- enough to ride out transient GitHub API
    blips without hammering the endpoint.
    """
    return base * (2 ** attempt) + random.uniform(0, max_jitter)


def request_with_retry(
    method: str,
    url: str,
    *,
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    max_jitter: float = MAX_JITTER,
    retry_statuses: tuple[int, ...] = (502, 503, 504, 429),
    **kwargs,
) -> requests.Response:
    """Execute an HTTP request with exponential backoff and jitter on failure.

    Retries on network errors (``ConnectionError``, ``Timeout``) and on
    server-side status codes listed in *retry_statuses*.  Non-retryable
    HTTP errors are raised immediately via ``raise_for_status()``.

    Parameters
    ----------
    method : str
        HTTP method (``"GET"``, ``"POST"``, ``"PUT"``, etc.).
    url : str
        Request URL.
    max_retries : int
        Total number of attempts (default 3).
    base_delay : float
        Base seconds for exponential backoff (default 2.0).
    max_jitter : float
        Maximum random jitter added to each delay (default 1.0).
    retry_statuses : tuple[int, ...]
        HTTP status codes that trigger a retry (default 502, 503, 504, 429).
    **kwargs
        Forwarded to ``requests.request()`` (headers, json, params, timeout, etc.).
    """
    last_err: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.request(method, url, **kwargs)
            if resp.status_code in retry_statuses and attempt < max_retries:
                delay = exponential_backoff_delay(attempt, base_delay, max_jitter)
                print(f"  Retry {attempt}/{max_retries} for {url} "
                      f"(status {resp.status_code}, waiting {delay:.1f}s)")
                time.sleep(delay)
                continue
            return resp
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_err = e
            if attempt < max_retries:
                delay = exponential_backoff_delay(attempt, base_delay, max_jitter)
                print(f"  Retry {attempt}/{max_retries} for {url} "
                      f"(error: {e}, waiting {delay:.1f}s)")
                time.sleep(delay)
            else:
                raise
    raise last_err  # type: ignore[misc]


def run_git_with_retry(
    *args: str,
    cwd: str,
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    """Run a git command with retry logic for push/fetch operations.

    Only retries on non-zero exit codes.  This is useful for ``git push``
    which can fail transiently due to network issues or remote lock
    contention.
    """
    last_result: subprocess.CompletedProcess[str] | None = None
    for attempt in range(1, max_retries + 1):
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result
        last_result = result
        if attempt < max_retries:
            delay = exponential_backoff_delay(attempt, base_delay)
            print(f"  git {' '.join(args)} failed (attempt {attempt}/{max_retries}), "
                  f"retrying in {delay:.1f}s: {result.stderr.strip()}")
            time.sleep(delay)
    return last_result  # type: ignore[return-value]
