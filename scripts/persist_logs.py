#!/usr/bin/env python3
"""Persist run results to the repository's logs directory."""

import json
import os
import re
import shutil
import subprocess
import sys


def run_git(*args: str, cwd: str) -> str:
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

    remote_url = run_git("remote", "get-url", "origin", cwd=repo_dir)
    if "github.com" in remote_url and github_token:
        authed_url = re.sub(
            r"https://github\.com/",
            f"https://x-access-token:{github_token}@github.com/",
            remote_url,
        )
        run_git("remote", "set-url", "origin", authed_url, cwd=repo_dir)

    branch = run_git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo_dir)
    result = subprocess.run(
        ["git", "push", "origin", branch],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"WARNING: git push failed: {result.stderr}")
        print("The default GITHUB_TOKEN may not have permission to push to the target repo.")
        print("Logs were committed locally but could not be pushed.")
    else:
        print(f"Logs pushed to {branch}")


if __name__ == "__main__":
    main()
