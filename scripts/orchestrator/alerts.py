"""Alert processing for orchestrator cycles.

Wraps the ``github_app/alerts`` module to provide a clean interface
for cycle-level alert handling without requiring the caller to manage
sys.path manipulation or import error handling.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

_PKG_DIR = pathlib.Path(__file__).resolve().parent
_SCRIPTS_DIR = _PKG_DIR.parent
_ROOT_DIR = _SCRIPTS_DIR.parent
_GITHUB_APP_DIR = _ROOT_DIR / "github_app"


def process_cycle_alerts(
    all_issues: list[dict[str, Any]],
    fp_fix_map: dict[str, dict[str, Any]],
    current_progress: list[dict[str, Any]],
    previous_progress: list[dict[str, Any]],
    orch_config: dict[str, Any],
    github_token: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run cycle alerts and return results dict."""
    if dry_run:
        return {"dry_run": True}

    if str(_GITHUB_APP_DIR) not in sys.path:
        sys.path.insert(0, str(_GITHUB_APP_DIR))
    try:
        from alerts import process_cycle_alerts as _process
        return _process(
            all_issues, fp_fix_map, current_progress, previous_progress,
            orch_config, github_token,
        )
    except ImportError:
        return {"error": "alerts module not available"}


def send_cycle_summary(
    cycle_results: dict[str, Any],
    dry_run: bool = False,
) -> None:
    """Send a cycle summary alert if the alerts module is available."""
    if dry_run:
        return

    if str(_GITHUB_APP_DIR) not in sys.path:
        sys.path.insert(0, str(_GITHUB_APP_DIR))
    try:
        from alerts import send_cycle_summary_alert
        send_cycle_summary_alert(cycle_results)
    except ImportError:
        pass
