#!/usr/bin/env python3
"""Check for an existing fork of the target repo and create one if needed.

This script is the first step in the CodeQL Devin Fixer pipeline.  It ensures
that the analysis runs against a *fork* in the user's GitHub account rather
than the original upstream repository.  This is important because:

* The user may not have push access to the upstream repo.
* Devin sessions need a repo where they can create branches and PRs.
* Scanning a fork keeps upstream unaffected.

The script requires a **Personal Access Token (PAT)** with ``repo`` scope.
The default ``secrets.GITHUB_TOKEN`` issued by GitHub Actions is an
installation token scoped only to the repo running the workflow -- it cannot
create forks or push to other repositories.

Environment variables
---------------------
GITHUB_TOKEN : str
    PAT with ``repo`` scope (required).
TARGET_REPO : str
    Full HTTPS URL of the upstream repository to fork.
DEFAULT_BRANCH : str
    Branch to sync after forking (default ``main``).
FORK_OWNER : str
    GitHub username that should own the fork.  In the workflow this is set
    from ``github.repository_owner`` so the script does not need to call
    the ``/user`` API (which fails with installation tokens).

Outputs (written to ``$GITHUB_OUTPUT``)
---------------------------------------
fork_url : str
    HTTPS URL of the fork (e.g. ``https://github.com/user/repo``).
fork_owner : str
    Owner of the fork.
fork_repo : str
    Repository name of the fork.
"""

import os
import sys
import time
import requests

try:
    from github_utils import gh_headers, normalize_repo_url, parse_repo_url  # noqa: F401
except ImportError:
    from scripts.github_utils import gh_headers, normalize_repo_url, parse_repo_url  # noqa: F401


def resolve_owner(token: str, fallback: str) -> str:
    """Determine the GitHub username that will own the fork.

    The primary source is the ``FORK_OWNER`` env var (passed as *fallback*),
    which is set from ``github.repository_owner`` in the workflow and is always
    available.  The ``/user`` API call is a secondary fallback for local
    testing with a PAT -- it will fail with an installation token.
    """
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
    """Check whether ``my_user`` already has a fork of ``owner/repo``.

    Uses the ``GET /repos/{my_user}/{repo}`` endpoint and verifies that the
    returned repository is actually a fork whose parent matches the target.
    Returns the repo JSON dict if a valid fork is found, otherwise ``None``.
    """
    resp = requests.get(
        f"https://api.github.com/repos/{my_user}/{repo}",
        headers=gh_headers(token),
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
    """Create a new fork of ``owner/repo`` under the authenticated user.

    After the API call returns, GitHub may still be copying data.  The
    function polls up to 12 times (60 s total) until the fork's ``size``
    field is non-zero, indicating the copy is complete.
    """
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
    """Bring the fork's default branch up to date with upstream.

    Uses the ``POST /repos/{owner}/{repo}/merge-upstream`` endpoint.  A 409
    response means the branch is already up to date, which is fine.
    """
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

    if not token:
        print("ERROR: GITHUB_TOKEN is required for fork operations.")
        print("Set the github_token input to a Personal Access Token (PAT) with 'repo' scope.")
        sys.exit(1)
    if not target_repo:
        print("ERROR: TARGET_REPO is required")
        sys.exit(1)

    owner, repo = parse_repo_url(target_repo)

    my_user = resolve_owner(token, fork_owner_hint)
    if not my_user:
        print("ERROR: Cannot determine fork owner.")
        print("Set FORK_OWNER env var or use a PAT with 'repo' scope.")
        sys.exit(1)

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
                print(f"ERROR: Could not create fork: {e}")
                print()
                print("The default GITHUB_TOKEN (Actions installation token) cannot create forks.")
                print("You need a Personal Access Token (PAT) with 'repo' scope.")
                print()
                print("Setup instructions:")
                print("  1. Go to https://github.com/settings/tokens")
                print("  2. Generate new token (classic) with 'repo' scope")
                print("  3. Copy the token")
                print("  4. Go to your repo Settings > Secrets and variables > Actions")
                print("  5. Create a new secret named GH_PAT with the token value")
                print("  6. In your workflow, change:")
                print("       github_token: ${{ secrets.GITHUB_TOKEN }}")
                print("     to:")
                print("       github_token: ${{ secrets.GH_PAT }}")
                sys.exit(1)

    _write_outputs(fork_url, my_user, repo)


def _write_outputs(fork_url: str, owner: str, repo: str) -> None:
    """Write fork details to ``$GITHUB_OUTPUT`` for downstream action steps."""
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"fork_url={fork_url}\n")
            f.write(f"fork_owner={owner}\n")
            f.write(f"fork_repo={repo}\n")
    print(f"FORK_URL={fork_url}")


if __name__ == "__main__":
    main()
