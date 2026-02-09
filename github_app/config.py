"""Configuration for the CodeQL Devin Fixer GitHub App.

All settings are loaded from environment variables.  Required variables
(``GITHUB_APP_ID``, ``GITHUB_APP_PRIVATE_KEY_PATH``, ``GITHUB_APP_WEBHOOK_SECRET``)
must be set before the server starts.  Optional variables control default
scan behaviour and can be overridden per-repo via ``.codeql-fixer.yml``.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppConfig:
    app_id: int
    private_key_path: str
    webhook_secret: str

    devin_api_key: str = ""

    default_batch_size: int = 5
    default_max_sessions: int = 25
    default_severity_threshold: str = "low"
    default_queries: str = "security-extended"
    default_branch: str = "main"

    server_host: str = "0.0.0.0"
    server_port: int = 3000
    debug: bool = False

    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> AppConfig:
        app_id_raw = os.environ.get("GITHUB_APP_ID", "")
        if not app_id_raw:
            logger.error("GITHUB_APP_ID is required")
            sys.exit(1)

        private_key_path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "")
        if not private_key_path:
            logger.error("GITHUB_APP_PRIVATE_KEY_PATH is required")
            sys.exit(1)

        webhook_secret = os.environ.get("GITHUB_APP_WEBHOOK_SECRET", "")
        if not webhook_secret:
            logger.error("GITHUB_APP_WEBHOOK_SECRET is required")
            sys.exit(1)

        return cls(
            app_id=int(app_id_raw),
            private_key_path=private_key_path,
            webhook_secret=webhook_secret,
            devin_api_key=os.environ.get("DEVIN_API_KEY", ""),
            default_batch_size=int(os.environ.get("DEFAULT_BATCH_SIZE", "5")),
            default_max_sessions=int(os.environ.get("DEFAULT_MAX_SESSIONS", "25")),
            default_severity_threshold=os.environ.get("DEFAULT_SEVERITY_THRESHOLD", "low"),
            default_queries=os.environ.get("DEFAULT_QUERIES", "security-extended"),
            default_branch=os.environ.get("DEFAULT_BRANCH", "main"),
            server_host=os.environ.get("SERVER_HOST", "0.0.0.0"),
            server_port=int(os.environ.get("SERVER_PORT", "3000")),
            debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )
