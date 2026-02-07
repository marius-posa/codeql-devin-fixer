#!/usr/bin/env python3
"""Check for an existing fork and create one if needed."""

import os
import re
import sys
import time
import requests


def parse_repo_url(url: str) -> tuple[str, str]:
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+)", url)
    if not m:
        print(f"ERROR: cannot parse repo URL: {url}")
        sys.exit(1)
    return m.group(1), m.group(2)


def resolve_owner(token: str, fallback: str) -> str:
    if fallback:
        return fallback
    try:
        resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["login"]
    except requests.exceptions.RequestException as e:
        print(f"WARNING: could not determine user from /user endpoint: {e}")
        print("Hint: set FORK_OWNER or use a Personal Access Token (PAT) with 'repo' scope.")
        return ""


def check_fork_exists(token: str, owner: str, repo: str, my_user: str) -> dict | None:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    resp = requests.get(
        f"https://api.github.com/repos/{my_user}/{repo}",
        headers=headers,
        timeout=30,
    )
    if resp.status_code == 200:
        data = resp.json()
        if data.get("fork"):
            parent = data.get("parent", {})
            if parent.get("full_name", "").lower() == f"{owner}/{repo}".lower():
                return data
            if not parent:
                return data
    return None


def create_fork(token: str, owner: str, repo: str) -> dict:
    print(f"Creating fork of {owner}/{repo}...")
    resp = requests.post(
        f"https://api.github.com/repos/{owner}/{repo}/forks",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
        json={"default_branch_only": False},
        timeout=60,
    )
    resp.raise_for_status()
    fork_data = resp.json()
    print(f"Fork created: {fork_data['html_url']}")

    for attempt in range(1, 13):
        time.sleep(5)
        check = requests.get(
            fork_data["url"],
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            timeout=30,
        )
        if check.status_code == 200:
            size = check.json().get("size", 0)
            if size > 0:
                print(f"Fork ready (attempt {attempt})")
                return check.json()
        print(f"Waiting for fork to be ready (attempt {attempt}/12)...")

    return fork_data


def sync_fork(token: str, my_user: str, repo: str, branch: str) -> None:
    print(f"Syncing fork {my_user}/{repo} with upstream {branch}...")
    resp = requests.post(
        f"https://api.github.com/repos/{my_user}/{repo}/merge-upstream",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
        json={"branch": branch},
        timeout=30,
    )
    if resp.status_code in (200, 409):
        print(f"Fork synced: {resp.json().get('message', 'ok')}")
    else:
        print(f"WARNING: sync returned {resp.status_code}: {resp.text}")


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    target_repo = os.environ.get("TARGET_REPO", "")
    default_branch = os.environ.get("DEFAULT_BRANCH", "main")
    fork_owner_hint = os.environ.get("FORK_OWNER", "")

    if not target_repo:
        print("ERROR: TARGET_REPO is required")
        sys.exit(1)

    owner, repo = parse_repo_url(target_repo)

    my_user = resolve_owner(token, fork_owner_hint)
    if not my_user:
        print("WARNING: Cannot determine fork owner. Falling back to original repo.")
        fork_url = f"https://github.com/{owner}/{repo}"
        _write_outputs(fork_url, owner, repo)
        return

    print(f"Fork owner: {my_user}")
    print(f"Target repo: {owner}/{repo}")

    if owner.lower() == my_user.lower():
        print("Target repo is already owned by you. No fork needed.")
        fork_url = f"https://github.com/{my_user}/{repo}"
    else:
        existing = check_fork_exists(token, owner, repo, my_user)
        if existing:
            print(f"Fork already exists: {existing['html_url']}")
            fork_url = existing["html_url"]
            sync_fork(token, my_user, repo, default_branch)
        else:
            try:
                fork_data = create_fork(token, owner, repo)
                fork_url = fork_data["html_url"]
                sync_fork(token, my_user, repo, default_branch)
            except requests.exceptions.RequestException as e:
                print(f"WARNING: Could not create fork: {e}")
                print("The default GITHUB_TOKEN cannot create forks.")
                print("To enable automatic forking, add a PAT with 'repo' scope as a secret.")
                print("Falling back to original repo URL.")
                fork_url = f"https://github.com/{owner}/{repo}"

    _write_outputs(fork_url, my_user, repo)


def _write_outputs(fork_url: str, owner: str, repo: str) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"fork_url={fork_url}\n")
            f.write(f"fork_owner={owner}\n")
            f.write(f"fork_repo={repo}\n")
    print(f"FORK_URL={fork_url}")


if __name__ == "__main__":
    main()
