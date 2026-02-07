#!/usr/bin/env python3
"""Persist run results to the repository's logs directory.

After every action run, the outputs (issues, batches, sessions, prompts) are
written to a timestamped directory under ``logs/`` in the *target repository*
(the fork).  This serves two purposes:

1. **Auditability** -- every run's results are committed to git, providing a
   permanent record of what was found and what sessions were created.
2. **Dashboard data source** -- ``generate_dashboard.py`` reads these logs
   to build historical metrics (runs over time, issues found, etc.).

The script copies JSON and text artefacts from the action's temporary output
directory into the repo's ``logs/run-{label}/`` directory, commits them, and
pushes to the fork.

Authentication note
-------------------
The ``GITHUB_TOKEN`` used here **must** be a PAT with ``repo`` scope.  The
default ``secrets.GITHUB_TOKEN`` only has permission to push to the repo
running the workflow (``codeql-devin-fixer``), not the fork.  If the push
fails the script prints a warning and continues -- the logs will still be
available as workflow artefacts even if they aren't committed.

Environment variables
---------------------
GITHUB_TOKEN : str
    PAT with ``repo`` scope for pushing to the fork.
TARGET_REPO : str
    Full HTTPS URL of the fork repository.
REPO_DIR : str
    Local path to the cloned fork.
RUN_LABEL : str
    Label for this run (e.g. ``run-11-2025-06-01-120000``).
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

from retry_utils import run_git_with_retry


def run_git(*args: str, cwd: str) -> str:
    """Run a git command and return stdout.  Prints stderr on failure."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def main() -> None:
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "output"
    repo_dir = os.environ.get("REPO_DIR", "")
    run_label = os.environ.get("RUN_LABEL", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    target_repo = os.environ.get("TARGET_REPO", "")

    if not repo_dir:
        print("ERROR: REPO_DIR is required")
        sys.exit(1)
    if not run_label:
        print("ERROR: RUN_LABEL is required")
        sys.exit(1)

    logs_base = os.path.join(repo_dir, "logs")
    run_dir = os.path.join(logs_base, run_label)
    os.makedirs(run_dir, exist_ok=True)

    files_to_copy = [
        "run_log.json",
        "issues.json",
        "batches.json",
        "sessions.json",
        "summary.md",
        "outcomes.json",
    ]

    for fname in files_to_copy:
        src = os.path.join(output_dir, fname)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(run_dir, fname))
            print(f"Copied {fname}")

    for entry in os.listdir(output_dir):
        if entry.startswith("prompt_batch_") and entry.endswith(".txt"):
            shutil.copy2(
                os.path.join(output_dir, entry),
                os.path.join(run_dir, entry),
            )
            print(f"Copied {entry}")

    manifest = {
        "run_label": run_label,
        "files": sorted(os.listdir(run_dir)),
    }
    with open(os.path.join(run_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    if not github_token:
        print("WARNING: GITHUB_TOKEN not set; skipping git push")
        return

    run_git("config", "user.email", "codeql-devin-fixer[bot]@users.noreply.github.com", cwd=repo_dir)
    run_git("config", "user.name", "codeql-devin-fixer[bot]", cwd=repo_dir)
    run_git("add", os.path.relpath(run_dir, repo_dir), cwd=repo_dir)

    status = run_git("status", "--porcelain", cwd=repo_dir)
    if not status:
        print("No changes to commit")
        return

    run_git("commit", "-m", f"chore: persist run logs for {run_label}", cwd=repo_dir)

    branch = run_git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo_dir)

    env = os.environ.copy()
    if github_token:
        askpass_script = _create_askpass_script(github_token)
        env["GIT_ASKPASS"] = askpass_script
        env["GIT_TERMINAL_PROMPT"] = "0"
        remote_url = run_git("remote", "get-url", "origin", cwd=repo_dir)
        parsed_remote = urlparse(remote_url)
        if parsed_remote.hostname == "github.com" and "@" in remote_url:
            clean_url = f"https://github.com{parsed_remote.path}"
            run_git("remote", "set-url", "origin", clean_url, cwd=repo_dir)

    result = run_git_with_retry("push", "origin", branch, cwd=repo_dir, env=env)
    logs_persisted = result.returncode == 0
    if not logs_persisted:
        print(f"WARNING: git push failed after retries: {result.stderr}")
        print("The default GITHUB_TOKEN may not have permission to push to the target repo.")
        print("Logs were committed locally but could not be pushed.")
    else:
        print(f"Logs pushed to {branch}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"logs_persisted={str(logs_persisted).lower()}\n")


def _create_askpass_script(token: str) -> str:
    """Create a temporary GIT_ASKPASS script that supplies the token.

    Using GIT_ASKPASS keeps the token out of remote URLs and process
    argument lists, preventing accidental exposure in logs or stack traces.
    """
    fd, path = tempfile.mkstemp(prefix="git_askpass_", suffix=".sh")
    with os.fdopen(fd, "w") as f:
        f.write("#!/bin/sh\n")
        f.write(f'echo "x-access-token:{token}"\n')
    os.chmod(path, stat.S_IRWXU)
    return path


if __name__ == "__main__":
    main()
