import os
import pathlib

RUNS_DIR= pathlib.Path(__file__).parent / "runs"
DEVIN_API_BASE = "https://api.devin.ai/v1"


def gh_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def devin_headers() -> dict:
    key = os.environ.get("DEVIN_API_KEY", "")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
