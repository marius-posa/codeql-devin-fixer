"""Centralised configuration for the CodeQL Devin Fixer pipeline.

Every environment variable consumed by the pipeline scripts is declared
here as a field on :class:`PipelineConfig`.  This serves as the single
source of truth for what configuration each script needs, and catches
missing or invalid values early -- before a long workflow run fails
partway through.

Usage
-----
::

    from pipeline_config import PipelineConfig

    cfg = PipelineConfig.from_env()
    print(cfg.target_repo)

Each script only reads the subset of fields it needs, but having them
all in one place makes it easy to audit the full surface area.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import TypedDict


class IssueLocation(TypedDict):
    file: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int


class ParsedIssue(TypedDict):
    id: str
    rule_id: str
    rule_name: str
    severity_tier: str
    cvss_score: float
    cwe_ids: list[str]
    cwe_family: str
    message: str
    locations: list[IssueLocation]
    fingerprint: str


class Batch(TypedDict):
    batch_id: int
    cwe_family: str
    severity_tier: str
    issues: list[ParsedIssue]


class SessionRecord(TypedDict):
    session_id: str
    session_url: str
    batch_id: int
    status: str
    issue_ids: list[str]


class TelemetryRecord(TypedDict):
    target_repo: str
    fork_url: str
    run_number: int
    run_id: str
    run_url: str
    run_label: str
    timestamp: str
    issues_found: int
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]
    batches_created: int
    sessions: list[SessionRecord]
    issue_fingerprints: list[dict[str, str | int]]
    zero_issue_run: bool


@dataclass(frozen=True)
class PipelineConfig:
    """Immutable snapshot of all pipeline environment variables.

    Fields are grouped by the script(s) that consume them.  Optional
    fields default to sensible values; required fields raise early if
    they are missing when the caller marks them as required via
    :meth:`validate`.
    """

    # -- Shared across scripts ------------------------------------------------
    github_token: str = ""
    target_repo: str = ""
    default_branch: str = "main"

    # -- parse_sarif.py -------------------------------------------------------
    batch_size: int = 5
    max_sessions: int = 25
    severity_threshold: str = "low"
    run_number: str = ""

    # -- dispatch_devin.py ----------------------------------------------------
    devin_api_key: str = ""
    max_acu_per_session: int | None = None
    dry_run: bool = False
    fork_url: str = ""
    run_id: str = ""
    max_failure_rate: int = 50

    # -- fork_repo.py ---------------------------------------------------------
    fork_owner: str = ""

    # -- persist_logs.py ------------------------------------------------------
    repo_dir: str = ""
    run_label: str = ""

    # -- persist_telemetry.py -------------------------------------------------
    action_repo: str = ""

    # -- generate_dashboard.py ------------------------------------------------
    logs_dir: str = "logs"
    dashboard_output_dir: str = "dashboard"

    # -- dispatch_devin.py (context-rich prompts / fix learning) --------------
    target_dir: str = ""
    telemetry_dir: str = ""

    @classmethod
    def from_env(cls) -> PipelineConfig:
        """Build a config from the current environment variables."""
        max_acu_raw = os.environ.get("MAX_ACU_PER_SESSION", "")
        max_acu = int(max_acu_raw) if max_acu_raw else None

        return cls(
            github_token=os.environ.get("GITHUB_TOKEN", ""),
            target_repo=os.environ.get("TARGET_REPO", ""),
            default_branch=os.environ.get("DEFAULT_BRANCH", "main"),
            batch_size=int(os.environ.get("BATCH_SIZE", "5")),
            max_sessions=int(os.environ.get("MAX_SESSIONS", "25")),
            severity_threshold=os.environ.get("SEVERITY_THRESHOLD", "low"),
            run_number=os.environ.get("RUN_NUMBER", ""),
            devin_api_key=os.environ.get("DEVIN_API_KEY", ""),
            max_acu_per_session=max_acu,
            dry_run=os.environ.get("DRY_RUN", "false").lower() == "true",
            fork_url=os.environ.get("FORK_URL", ""),
            run_id=os.environ.get("RUN_ID", ""),
            max_failure_rate=int(os.environ.get("MAX_FAILURE_RATE", "50")),
            fork_owner=os.environ.get("FORK_OWNER", ""),
            repo_dir=os.environ.get("REPO_DIR", ""),
            run_label=os.environ.get("RUN_LABEL", ""),
            action_repo=os.environ.get("ACTION_REPO", ""),
            logs_dir=os.environ.get("LOGS_DIR", "logs"),
            dashboard_output_dir=os.environ.get("DASHBOARD_OUTPUT_DIR", "dashboard"),
            target_dir=os.environ.get("TARGET_DIR", ""),
            telemetry_dir=os.environ.get("TELEMETRY_DIR", ""),
        )

    def validate(self, required: list[str]) -> None:
        """Check that the named fields are non-empty, exiting on failure.

        Parameters
        ----------
        required : list[str]
            Field names that must be truthy for the calling script.

        Raises
        ------
        SystemExit
            Printed error listing every missing variable so the user can
            fix them all in one go rather than discovering them one by one.
        """
        missing = [
            name for name in required if not getattr(self, name, None)
        ]
        if missing:
            env_names = [name.upper() for name in missing]
            print(
                f"ERROR: Missing required configuration: {', '.join(env_names)}\n"
                "Set these environment variables before running the pipeline."
            )
            sys.exit(1)
