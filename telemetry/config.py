import os
import pathlib
import sys

RUNS_DIR = pathlib.Path(__file__).parent / "runs"

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from devin_api import DEVIN_API_BASE, headers as _devin_headers  # noqa: E402

from github_utils import gh_headers as _shared_gh_headers  # noqa: E402


def gh_headers() -> dict[str, str]:
    """Return GitHub API headers using the shared utility."""
    token = os.environ.get("GITHUB_TOKEN", "")
    return _shared_gh_headers(token)


def devin_headers() -> dict[str, str]:
    """Return Devin API headers using the shared utility."""
    key = os.environ.get("DEVIN_API_KEY", "")
    return _devin_headers(key)
