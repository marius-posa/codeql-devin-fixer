import os
import pathlib

RUNS_DIR = pathlib.Path(__file__).parent / "runs"
DEVIN_API_BASE = "https://api.devin.ai/v1"


def gh_headers(token: str = "") -> dict:
    if not token:
        token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def devin_headers(api_key: str = "") -> dict:
    if not api_key:
        api_key = os.environ.get("DEVIN_API_KEY", "")
    return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}


def get_action_repo(override: str = "") -> str:
    return override or os.environ.get("ACTION_REPO", "")
