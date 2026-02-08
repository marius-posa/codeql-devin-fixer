"""Tests for PipelineConfig dataclass."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.pipeline_config import PipelineConfig


class TestPipelineConfigDefaults:
    def test_default_values(self):
        cfg = PipelineConfig()
        assert cfg.github_token == ""
        assert cfg.target_repo == ""
        assert cfg.default_branch == "main"
        assert cfg.mode == "basic"
        assert cfg.batch_size == 5
        assert cfg.max_sessions == 25
        assert cfg.severity_threshold == "low"
        assert cfg.dry_run is False
        assert cfg.max_acu_per_session is None

    def test_frozen(self):
        cfg = PipelineConfig()
        with pytest.raises(AttributeError):
            cfg.batch_size = 10  # type: ignore[misc]


class TestPipelineConfigFromEnv:
    def test_reads_env_vars(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "tok123")
        monkeypatch.setenv("TARGET_REPO", "owner/repo")
        monkeypatch.setenv("BATCH_SIZE", "10")
        monkeypatch.setenv("SEVERITY_THRESHOLD", "high")
        monkeypatch.setenv("DRY_RUN", "true")
        monkeypatch.setenv("MAX_ACU_PER_SESSION", "50")
        monkeypatch.setenv("MODE", "orchestrator")
        cfg = PipelineConfig.from_env()
        assert cfg.github_token == "tok123"
        assert cfg.target_repo == "owner/repo"
        assert cfg.batch_size == 10
        assert cfg.severity_threshold == "high"
        assert cfg.dry_run is True
        assert cfg.max_acu_per_session == 50
        assert cfg.mode == "orchestrator"

    def test_missing_env_uses_defaults(self, monkeypatch):
        for k in ("GITHUB_TOKEN", "TARGET_REPO", "BATCH_SIZE", "MAX_SESSIONS",
                   "SEVERITY_THRESHOLD", "RUN_NUMBER", "DEVIN_API_KEY",
                   "MAX_ACU_PER_SESSION", "DRY_RUN", "FORK_URL", "RUN_ID",
                   "FORK_OWNER", "REPO_DIR", "RUN_LABEL", "ACTION_REPO",
                   "LOGS_DIR", "DASHBOARD_OUTPUT_DIR", "DEFAULT_BRANCH",
                   "MODE"):
            monkeypatch.delenv(k, raising=False)
        cfg = PipelineConfig.from_env()
        assert cfg.batch_size == 5
        assert cfg.max_sessions == 25
        assert cfg.dry_run is False
        assert cfg.mode == "basic"


class TestPipelineConfigValidate:
    def test_validate_passes_when_present(self):
        cfg = PipelineConfig(github_token="tok", target_repo="owner/repo")
        cfg.validate(["github_token", "target_repo"])

    def test_validate_exits_when_missing(self):
        cfg = PipelineConfig()
        with pytest.raises(SystemExit):
            cfg.validate(["github_token", "target_repo"])

    def test_validate_reports_all_missing(self, capsys):
        cfg = PipelineConfig()
        with pytest.raises(SystemExit):
            cfg.validate(["github_token", "devin_api_key"])
        output = capsys.readouterr().out
        assert "GITHUB_TOKEN" in output
        assert "DEVIN_API_KEY" in output
