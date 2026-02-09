"""Tests for SARIF validation and schema version envelopes."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.parse_sarif import validate_sarif, BATCHES_SCHEMA_VERSION, ISSUES_SCHEMA_VERSION


MINIMAL_SARIF = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeQL", "rules": []}},
            "results": [],
        }
    ],
}


class TestValidateSarif:
    def test_valid_sarif_passes(self):
        validate_sarif(MINIMAL_SARIF, "test.sarif")

    def test_missing_version_raises(self):
        bad = {"$schema": "...", "runs": []}
        with pytest.raises(ValueError, match="missing required 'version'"):
            validate_sarif(bad, "test.sarif")

    def test_missing_runs_raises(self):
        bad = {"version": "2.1.0"}
        with pytest.raises(ValueError, match="missing required 'runs'"):
            validate_sarif(bad, "test.sarif")

    def test_runs_not_list_raises(self):
        bad = {"version": "2.1.0", "runs": "not-a-list"}
        with pytest.raises(ValueError, match="'runs' must be a JSON array"):
            validate_sarif(bad, "test.sarif")

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="SARIF root must be a JSON object"):
            validate_sarif([], "test.sarif")

    def test_unexpected_version_warns(self, capfd):
        sarif = {"version": "1.0.0", "runs": []}
        validate_sarif(sarif, "test.sarif")
        assert "unexpected SARIF version" in capfd.readouterr().err

    def test_empty_runs_passes(self):
        sarif = {"version": "2.1.0", "runs": []}
        validate_sarif(sarif, "test.sarif")


class TestSchemaVersionConstants:
    def test_batches_version_is_string(self):
        assert isinstance(BATCHES_SCHEMA_VERSION, str)
        assert BATCHES_SCHEMA_VERSION == "1.0"

    def test_issues_version_is_string(self):
        assert isinstance(ISSUES_SCHEMA_VERSION, str)
        assert ISSUES_SCHEMA_VERSION == "1.0"
