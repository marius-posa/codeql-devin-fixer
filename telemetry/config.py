import os
import pathlib
import sys

RUNS_DIR = pathlib.Path(__file__).parent / "runs"

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from devin_api import DEVIN_API_BASE  # noqa: E402

from github_utils import gh_headers as _shared_gh_headers  # noqa: E402


def gh_headers() -> dict:
    """Return GitHub API headers using the shared utility."""
    token = os.environ.get("GITHUB_TOKEN", "")
    return _shared_gh_headers(token)


def devin_headers() -> dict:
    key = os.environ.get("DEVIN_API_KEY", "")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
