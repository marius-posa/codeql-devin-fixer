"""Trigger a CodeQL scan using the existing pipeline scripts.

This module bridges the GitHub App server with the existing analysis
pipeline.  Instead of running inside a GitHub Actions runner, it
invokes the pipeline scripts directly as subprocesses with the
appropriate environment variables set.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from github_app.log_utils import sanitize_log

log = logging.getLogger(__name__)

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"

_SAFE_REPO_URL_RE = re.compile(
    r"^https://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})+/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(?:\.git)?$"
)


def _validate_repo_url(url: str) -> str:
    if not _SAFE_REPO_URL_RE.match(url):
        raise ValueError(f"Invalid repository URL format: {url}")
    return url


def trigger_scan(scan_config: dict) -> dict:
    target_repo = scan_config.get("target_repo", "")
    github_token = scan_config.get("github_token", "")
    devin_api_key = scan_config.get("devin_api_key", "")
    batch_size = scan_config.get("batch_size", 5)
    max_sessions = scan_config.get("max_sessions", 25)
    severity_threshold = scan_config.get("severity_threshold", "low")
    queries = scan_config.get("queries", "security-extended")
    default_branch = scan_config.get("default_branch", "main")
    dry_run = scan_config.get("dry_run", False)

    if not target_repo:
        return {"error": "target_repo is required"}
    if not devin_api_key and not dry_run:
        return {"error": "devin_api_key is required for non-dry-run scans"}

    env = {
        **os.environ,
        "TARGET_REPO": target_repo,
        "DEFAULT_BRANCH": default_branch,
        "BATCH_SIZE": str(batch_size),
        "MAX_SESSIONS": str(max_sessions),
        "SEVERITY_THRESHOLD": severity_threshold,
        "DRY_RUN": str(dry_run).lower(),
        "DEVIN_API_KEY": devin_api_key,
    }
    if github_token:
        env["GITHUB_TOKEN"] = github_token

    work_dir = tempfile.mkdtemp(prefix="codeql-fixer-")
    output_dir = os.path.join(work_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    log.info("Starting scan for %s in %s", sanitize_log(target_repo), work_dir)

    steps: list[dict] = []

    fork_result = _run_fork(env, work_dir, target_repo, default_branch, github_token)
    steps.append({"step": "fork", **fork_result})
    if fork_result.get("error"):
        return {"status": "failed", "steps": steps}

    fork_url = fork_result.get("fork_url", target_repo)
    env["FORK_URL"] = fork_url
    env["SCAN_REPO_URL"] = fork_url

    clone_dir = os.path.join(work_dir, "target-repo")
    clone_result = _run_clone(fork_url, clone_dir, github_token)
    steps.append({"step": "clone", **clone_result})
    if clone_result.get("error"):
        return {"status": "failed", "steps": steps}

    env["TARGET_DIR"] = clone_dir

    parse_result = _run_parse(env, clone_dir, output_dir, queries)
    steps.append({"step": "parse", **parse_result})
    if parse_result.get("error"):
        return {"status": "failed", "steps": steps}

    batches_path = os.path.join(output_dir, "batches.json")
    if not os.path.isfile(batches_path):
        steps.append({"step": "dispatch", "status": "skipped", "reason": "no batches"})
        return {"status": "completed", "steps": steps, "issues_found": 0}

    dispatch_result = _run_dispatch(env, batches_path, output_dir)
    steps.append({"step": "dispatch", **dispatch_result})

    return {"status": "completed", "steps": steps}


def _run_fork(
    env: dict, work_dir: str, target_repo: str,
    default_branch: str, github_token: str,
) -> dict:
    if not github_token:
        return {"status": "skipped", "fork_url": target_repo}

    fork_env = {
        **env,
        "TARGET_REPO": target_repo,
        "DEFAULT_BRANCH": default_branch,
        "FORK_OWNER": "",
    }

    output_file = os.path.join(work_dir, "fork_output")
    fork_env["GITHUB_OUTPUT"] = output_file
    Path(output_file).touch()

    try:
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "fork_repo.py")],
            env=fork_env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            log.error("Fork failed: %s", result.stderr)
            return {"error": result.stderr.strip(), "status": "failed"}

        fork_url = target_repo
        if os.path.isfile(output_file):
            with open(output_file) as f:
                for line in f:
                    if line.startswith("fork_url="):
                        fork_url = line.split("=", 1)[1].strip()
                        break

        return {"status": "ok", "fork_url": fork_url}
    except subprocess.TimeoutExpired:
        return {"error": "fork timed out", "status": "failed"}
    except Exception as exc:
        return {"error": str(exc), "status": "failed"}


def _redact_token(text: str, token: str) -> str:
    if token and token in text:
        return text.replace(token, "***")
    return text


def _run_clone(repo_url: str, clone_dir: str, github_token: str) -> dict:
    try:
        repo_url = _validate_repo_url(repo_url)
        cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        clone_env = {**os.environ}
        if github_token:
            clone_env["GIT_ASKPASS"] = "echo"
            clone_env["GIT_TERMINAL_PROMPT"] = "0"
            import base64
            creds = base64.b64encode(
                f"x-access-token:{github_token}".encode()
            ).decode()
            cmd = [
                "git",
                "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {creds}",
                "clone", "--depth", "1", "--single-branch",
            ]
        cmd.extend(["--", repo_url, clone_dir])

        result = subprocess.run(
            cmd,
            env=clone_env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            err = _redact_token(result.stderr.strip(), github_token)
            return {"error": err, "status": "failed"}
        return {"status": "ok"}
    except subprocess.TimeoutExpired:
        return {"error": "clone timed out", "status": "failed"}
    except Exception as exc:
        return {"error": _redact_token(str(exc), github_token), "status": "failed"}


def _run_parse(
    env: dict, clone_dir: str, output_dir: str, queries: str,
) -> dict:
    log.info("Note: CodeQL analysis requires a GitHub Actions runner.")
    log.info("The GitHub App triggers scans via workflow dispatch.")

    sarif_dir = os.path.join(os.path.dirname(output_dir), "codeql-results")
    os.makedirs(sarif_dir, exist_ok=True)

    sarif_files = list(Path(sarif_dir).glob("*.sarif"))
    if not sarif_files:
        log.info("No SARIF files found; CodeQL must run in CI.")
        return {
            "status": "pending",
            "message": "CodeQL analysis must run in a GitHub Actions environment",
        }

    try:
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "parse_sarif.py"), sarif_dir, output_dir],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "status": "failed"}
        return {"status": "ok"}
    except Exception as exc:
        return {"error": str(exc), "status": "failed"}


def _run_dispatch(env: dict, batches_path: str, output_dir: str) -> dict:
    if env.get("DRY_RUN", "false") == "true":
        return {"status": "dry_run"}

    try:
        result = subprocess.run(
            [sys.executable, str(_SCRIPTS_DIR / "dispatch_devin.py"), batches_path, output_dir],
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "status": "failed"}

        sessions_file = os.path.join(output_dir, "sessions.json")
        sessions = []
        if os.path.isfile(sessions_file):
            with open(sessions_file) as f:
                sessions = json.load(f)

        return {
            "status": "ok",
            "sessions_created": len(sessions),
        }
    except subprocess.TimeoutExpired:
        return {"error": "dispatch timed out", "status": "failed"}
    except Exception as exc:
        return {"error": str(exc), "status": "failed"}
